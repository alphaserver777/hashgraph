"""Core MDRJ-DAG node implementation."""
from __future__ import annotations

import asyncio
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
        frontier = self.storage.get_frontier()
        frontier_ids = [fid for fid, _ in frontier]
        if len(frontier_ids) < 2:
            anchors = self._anchor_ids()
            for anchor in anchors:
                if anchor not in frontier_ids:
                    frontier_ids.append(anchor)
                if len(frontier_ids) >= 2:
                    break
        if len(frontier_ids) < 2:
            # Repeat available nodes if we still fall short (early bootstrap)
            frontier_ids = (frontier_ids + self._anchor_ids())[:2]
        else:
            frontier_ids = frontier_ids[:2]
        merged_clock = self.vector_clock.copy()
        for _, vclock in frontier:
            merged_clock = merged_clock.merge(vclock)
        local_clock = merged_clock.increment(self.config.node_id)
        event = Event.create(
            cls_name=cls_name,
            source=self.config.node_id,
            ts_local=ts,
            vclock=local_clock.to_dict(),
            parents=frontier_ids,
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

    def _sign_payload(self, payload: Mapping[str, object]) -> str:
        if not self.config.security.hmac_key:
            return ""
        return hmac_signature(self.config.security.hmac_key, payload)

    def _anchor_ids(self) -> List[str]:
        if self._anchors:
            return self._anchors
        events = self.storage.list_events(limit=10)
        anchors = [event.id for event in events if event.source == "genesis"]
        if len(anchors) < 2:
            anchors.extend(event.id for event in events if event.source != "genesis")
        self._anchors = anchors[:2]
        return self._anchors

    def _bootstrap_genesis(self) -> None:
        if self.storage.event_count() > 0:
            # ensure anchors cached for restarts
            self._anchor_ids()
            return
        anchors: List[str] = []
        for idx in range(2):
            payload = {"anchor": idx, "node": self.config.node_id}
            event = Event.create(
                cls_name=EventClass.C,
                source="genesis",
                ts_local=utc_timestamp(),
                vclock={},
                parents=[],
                payload=payload,
            )
            envelope = Envelope(event=event, path_meta=[{"node": "genesis", "ts": utc_timestamp()}])
            event.consensus_ts = event.ts_local
            self.storage.store_envelope(envelope, envelope.event.ts_local)
            anchors.append(event.id)
            self._notify_viz(envelope.event, stored=True, metrics=None)
        self._anchors = anchors

    # ------------------------------------------------------------------
    # Visualization
    def subscribe_visualizer(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._viz_subscribers.add(queue)
        return queue

    def unsubscribe_visualizer(self, queue: asyncio.Queue) -> None:
        self._viz_subscribers.discard(queue)

    def _notify_viz(self, event: Event, *, stored: bool, metrics: Optional[Dict[str, object]]) -> None:
        if not self._viz_subscribers:
            return
        payload: Dict[str, object] = {
            "type": "event",
            "stored": stored,
            "event": event.to_dict(),
        }
        if metrics is not None:
            payload["metrics"] = metrics
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
