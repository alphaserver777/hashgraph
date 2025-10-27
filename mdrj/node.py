"""Core MDRJ-DAG node implementation."""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, List, Mapping, Optional

import aiohttp
from aiohttp import web

from .config import NodeConfig
from .consensus import ConsensusEngine
from .gossip import GossipEngine
from .metrics import MetricsEngine
from .models import Envelope, Event, EventClass, PeerInfo
from .prioritization import Prioritizer
from .storage import DAGStorage
from .utils import hmac_signature, utc_timestamp
from .vectorclock import VectorClock


class NodeState(str, Enum):
    STARTED = "STARTED"
    ISOLATED = "ISOLATED"
    MERGING = "MERGING"
    RUN = "RUN"


@dataclass
class EventEmission:
    event: Event
    stored: bool


class Node:
    def __init__(self, config: NodeConfig) -> None:
        self.config = config
        self.state = NodeState.STARTED
        self.storage = DAGStorage(config.storage.sqlite_path)
        self.vector_clock = VectorClock()
        self.consensus = ConsensusEngine(config.node_id)
        self.prioritizer = Prioritizer(config.profile, config.gossip, config.prioritization)
        self.metrics = MetricsEngine(
            self.storage, config.gossip, config.profile.memory_mb, config.profile.bw_kbps
        )
        self._peers: Dict[str, PeerInfo] = {
            addr: PeerInfo(address=addr) for addr in config.peers
        }
        for peer in self._peers.values():
            self.storage.upsert_peer(peer.address, utc_timestamp(), healthy=True)
        self._anchors: List[str] = []
        self._session: Optional[aiohttp.ClientSession] = None
        self._gossip: Optional[GossipEngine] = None
        self._http_runner = None
        self._http_site = None
        self._loop_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._viz_subscribers: set[asyncio.Queue] = set()
        self._clear_tokens: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._bootstrap_genesis()
        self._session = aiohttp.ClientSession()
        self._gossip = GossipEngine(
            node_id=self.config.node_id,
            storage=self.storage,
            prioritizer=self.prioritizer,
            metrics=self.metrics,
            peer_provider=self.list_peers,
            session=self._session,
            fan_out=self.config.gossip.fan_out,
            period_sec=self.config.gossip.period_sec,
        )
        self._prime_gossip()
        await self._gossip.start()
        from .api import build_app

        app = build_app(self)
        runner = web.AppRunner(app)
        await runner.setup()
        host, port = self.config.listen.split(":")
        site = web.TCPSite(runner, host, int(port))
        await site.start()

        self._http_runner = runner
        self._http_site = site
        self.state = NodeState.RUN
        self.metrics.update_peer_health(self.list_peers(), self._quorum())

    async def stop(self) -> None:
        if self._gossip:
            await self._gossip.stop()
            self._gossip = None
        if self._session:
            await self._session.close()
            self._session = None
        if self._http_site:
            await self._http_site.stop()
            self._http_site = None
        if self._http_runner:
            await self._http_runner.cleanup()
            self._http_runner = None
        self.storage.close()
        self.state = NodeState.STARTED
        self._loop = None

    # ------------------------------------------------------------------
    # Peer management
    def list_peers(self) -> List[PeerInfo]:
        return list(self._peers.values())

    def register_peer(self, address: str) -> None:
        self._peers[address] = PeerInfo(address=address)
        self.storage.upsert_peer(address, utc_timestamp(), healthy=True)
        self.metrics.update_peer_health(self.list_peers(), self._quorum())
        if self._gossip:
            events = self.storage.list_events(limit=256)
            for event in events:
                self._gossip.add_pending(event.id)

    def _quorum(self) -> int:
        peers = len(self._peers) + 1
        return max(1, peers // 2 + 1)

    # ------------------------------------------------------------------
    # Events
    async def emit_event(self, cls_name: EventClass, payload: Mapping[str, object]) -> EventEmission:
        ts = utc_timestamp()
        parents: List[str] = []
        self_parent = self.storage.latest_event_by_source(self.config.node_id)
        if self_parent:
            parents.append(self_parent.id)
        recent_events = self.storage.list_recent_events(limit=256)
        other_candidates = [
            event.id
            for event in recent_events
            if event.source != self.config.node_id and event.id not in parents
        ]
        if other_candidates:
            parents.append(random.choice(other_candidates))
        anchors = self._anchor_ids()
        for anchor in anchors:
            if len(parents) >= 2:
                break
            if anchor not in parents:
                parents.append(anchor)
        parents = parents[:2]
        merged_clock = self.vector_clock.copy()
        for parent_id in parents:
            parent_event = self.storage.get_event(parent_id)
            if parent_event:
                merged_clock = merged_clock.merge(parent_event.vclock)
        local_clock = merged_clock.increment(self.config.node_id)
        event = Event.create(
            cls_name=cls_name,
            source=self.config.node_id,
            ts_local=ts,
            vclock=local_clock.to_dict(),
            parents=parents,
            payload=payload,
            sig=self._sign_payload(payload) if self.config.security.hmac_key else None,
        )
        envelope = Envelope(event=event, path_meta=[{"node": self.config.node_id, "ts": ts}])
        stored = self._persist_envelope(envelope)
        self.vector_clock = local_clock.merge(event.vclock)
        self.metrics.update_peer_health(self.list_peers(), self._quorum())
        return EventEmission(event=event, stored=stored)

    def _persist_envelope(self, envelope: Envelope) -> bool:
        arrival_ts = utc_timestamp()
        consensus = self.consensus.compute_timestamp(envelope, arrival_ts)
        envelope.event.consensus_ts = consensus.consensus_ts
        stored = self.storage.store_envelope(envelope, consensus.consensus_ts)
        self.vector_clock = self.vector_clock.merge(envelope.event.vclock)
        if stored:
            self.metrics.record_merge_quality(self._reconstruction_ratio())
            if self._gossip:
                self._gossip.add_pending(envelope.event.id)
            snapshot = self.metrics_snapshot()
            self._notify_viz(envelope.event, stored=True, metrics=snapshot)
        return stored

    def ingest_envelopes(self, envelopes: Iterable[Envelope]) -> List[str]:
        new_ids: List[str] = []
        for envelope in envelopes:
            stored = self._persist_envelope(envelope)
            if stored:
                new_ids.append(envelope.event.id)
        self.metrics.update_peer_health(self.list_peers(), self._quorum())
        return new_ids

    def _reconstruction_ratio(self) -> float:
        events = self.storage.list_events(limit=1000)
        total_edges = 0
        missing = 0
        cache: Dict[str, bool] = {}
        for event in events:
            for parent in event.parents:
                total_edges += 1
                if parent in cache:
                    exists = cache[parent]
                else:
                    exists = self.storage.get_event(parent) is not None
                    cache[parent] = exists
                if not exists:
                    missing += 1
        if total_edges == 0:
            return 1.0
        return max(0.0, 1 - missing / total_edges)

    def _clear_events_local(self) -> Dict[str, object]:
        """Purge DAG locally and reinitialize anchors."""
        self.storage.clear_events()
        self.vector_clock = VectorClock()
        self._anchors = []
        self.metrics.reset()
        reset_metrics = self.metrics_snapshot()
        self._notify_viz_reset(reset_metrics)
        self._bootstrap_genesis(force=True)
        self.metrics.update_peer_health(self.list_peers(), self._quorum())
        return reset_metrics

    def _mark_clear_token(self, token: str) -> bool:
        now = time.time()
        expiry = now - 300
        to_remove = [key for key, ts in self._clear_tokens.items() if ts < expiry]
        for key in to_remove:
            self._clear_tokens.pop(key, None)
        if token in self._clear_tokens:
            return False
        self._clear_tokens[token] = now
        if len(self._clear_tokens) > 128:
            oldest = min(self._clear_tokens.items(), key=lambda item: item[1])[0]
            self._clear_tokens.pop(oldest, None)
        return True

    async def clear_events(self, token: str, propagate: bool = True) -> Dict[str, object]:
        if not token:
            raise ValueError("clear token required")
        if not self._mark_clear_token(token):
            return self.metrics_snapshot()
        reset_metrics = await asyncio.to_thread(self._clear_events_local)
        if propagate:
            await self._propagate_clear(token)
        return reset_metrics

    def _sign_payload(self, payload: Mapping[str, object]) -> str:
        if not self.config.security.hmac_key:
            return ""
        return hmac_signature(self.config.security.hmac_key, payload)

    def _anchor_ids(self) -> List[str]:
        if self._anchors:
            return self._anchors
        events = self.storage.list_events(limit=20)
        anchors: List[str] = []
        for event in events:
            if (
                isinstance(event.payload, dict)
                and event.payload.get("genesis")
                and event.id not in anchors
            ):
                anchors.append(event.id)
        if not anchors and events:
            anchors.append(events[0].id)
        self._anchors = anchors
        return self._anchors

    def _bootstrap_genesis(self, *, force: bool = False) -> None:
        if not force and self.storage.event_count() > 0:
            # ensure anchors cached for restarts
            self._anchor_ids()
            return
        payload = {"anchor": 0, "node": self.config.node_id, "genesis": True}
        event = Event.create(
            cls_name=EventClass.C,
            source=self.config.node_id,
            ts_local=utc_timestamp(),
            vclock={},
            parents=[],
            payload=payload,
        )
        envelope = Envelope(
            event=event, path_meta=[{"node": self.config.node_id, "ts": utc_timestamp()}]
        )
        event.consensus_ts = event.ts_local
        self.storage.store_envelope(envelope, envelope.event.ts_local)
        if self._gossip:
            self._gossip.add_pending(event.id)
        self._anchors = [event.id]
        self._notify_viz(envelope.event, stored=True, metrics=self.metrics_snapshot())

    def _prime_gossip(self) -> None:
        if not self._gossip:
            return
        events = self.storage.list_events(limit=1000)
        for event in events:
            self._gossip.add_pending(event.id)

    async def _propagate_clear(self, token: str) -> None:
        if not self._session:
            return
        peers = self.list_peers()
        if not peers:
            return
        payload = {"token": token, "propagate": True}
        tasks = [
            self._send_clear_request(peer.address, payload)
            for peer in peers
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_clear_request(self, address: str, payload: Dict[str, object]) -> None:
        url = f"http://{address}/viz/clear"
        try:
            async with self._session.post(url, json=payload, timeout=5) as resp:
                await resp.read()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Visualization
    def subscribe_visualizer(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._viz_subscribers.add(queue)
        return queue

    def unsubscribe_visualizer(self, queue: asyncio.Queue) -> None:
        self._viz_subscribers.discard(queue)

    def _notify_viz(self, event: Event, *, stored: bool, metrics: Optional[Dict[str, object]]) -> None:
        payload: Dict[str, object] = {
            "type": "event",
            "stored": stored,
            "event": event.to_dict(),
        }
        if metrics is not None:
            payload["metrics"] = metrics
        self._broadcast_viz(payload)

    def _notify_viz_reset(self, metrics: Optional[Dict[str, object]]) -> None:
        payload: Dict[str, object] = {"type": "reset"}
        if metrics is not None:
            payload["metrics"] = metrics
        self._broadcast_viz(payload)

    def _broadcast_viz(self, payload: Dict[str, object]) -> None:
        if not self._viz_subscribers:
            return
        loop = self._loop
        for queue in list(self._viz_subscribers):
            if loop and loop.is_running():
                loop.call_soon_threadsafe(self._enqueue_viz, queue, payload)
            else:
                self._enqueue_viz(queue, payload)

    @staticmethod
    def _enqueue_viz(queue: asyncio.Queue, payload: Dict[str, object]) -> None:
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    # ------------------------------------------------------------------
    # Status / metrics
    def status(self) -> Dict[str, object]:
        return {
            "node_id": self.config.node_id,
            "state": self.state.value,
            "peers": [peer.to_dict() for peer in self.list_peers()],
            "profile": {
                "role": self.config.profile.role,
                "memory_mb": self.config.profile.memory_mb,
                "bw_kbps": self.config.profile.bw_kbps,
                "threat_level": self.config.profile.threat_level,
            },
        }

    def metrics_snapshot(self) -> Dict[str, object]:
        snap = self.metrics.snapshot()
        return {
            "A_est": snap.a_est,
            "T_gossip": snap.t_gossip,
            "K_r": snap.k_r,
            "C_mem": snap.c_mem,
            "C_net": snap.c_net,
            "event_count": snap.event_count,
        }
