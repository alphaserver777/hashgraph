"""Core MDRJ-DAG node implementation."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import secrets
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, List, Mapping, Optional

import aiohttp
from aiohttp import web

from .config import NodeConfig
from .consensus import ConsensusEngine
from .gossip import GossipEngine
from .linux_ingest import LinuxAuthLogIngestor, LinuxIngestStatus
from .metrics import MetricsEngine
from .models import Envelope, Event, EventClass, PeerInfo
from .prioritization import Prioritizer
from .simulation import SCENARIOS, scenario_payload
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


logger = logging.getLogger(__name__)


class Node:
    def __init__(self, config: NodeConfig) -> None:
        self.config = config
        self.state = NodeState.STARTED
        self.storage = DAGStorage(config.storage.sqlite_path)
        self.vector_clock = VectorClock()
        self.consensus = ConsensusEngine(config.node_id, bias_map=self._build_bias_map())
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
        self._simulation_task: Optional[asyncio.Task] = None
        self._simulation_stop = asyncio.Event()
        self._simulation_stop.set()
        self._simulation_token: Optional[str] = None
        self._consensus_stop = asyncio.Event()
        self._consensus_stop.set()
        self._consensus_task: Optional[asyncio.Task] = None
        self._consensus_mismatch: Dict[str, int] = {}
        self._genesis_counter = 0
        self._linux_ingest_task: Optional[asyncio.Task] = None
        self._linux_ingest_stop = asyncio.Event()
        self._linux_ingest_stop.set()
        self._linux_ingestor: Optional[LinuxAuthLogIngestor] = None
        self._linux_ingest_status = LinuxIngestStatus(
            enabled=config.linux_ingest.enabled,
            source_type=config.linux_ingest.source_type,
            source_path=config.linux_ingest.auth_log_path,
            host_id=config.linux_ingest.host_id or config.node_id,
        )

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
        await self._push_initial_events()
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
        self._consensus_stop.clear()
        self._consensus_task = asyncio.create_task(self._consensus_monitor_loop())
        if self.config.linux_ingest.enabled:
            self._start_linux_ingest()

    async def stop(self) -> None:
        if self.simulation_running():
            await self.stop_simulation()
        if self._linux_ingest_task:
            self._linux_ingest_stop.set()
            try:
                await self._linux_ingest_task
            except Exception:
                logger.exception("Error while stopping Linux ingest")
            self._linux_ingest_task = None
        if self._consensus_task:
            self._consensus_stop.set()
            try:
                await self._consensus_task
            except Exception:
                logger.exception("Error while stopping consensus monitor")
            self._consensus_task = None
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
        if stored and event.cls in (EventClass.A, EventClass.B):
            await self._broadcast_event(event.id)
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
            self._schedule_fast_fanout(envelope.event.id)
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
        self.storage.replace_incidents([])
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

    def list_incidents(self) -> List[Dict[str, object]]:
        return self.storage.list_incidents()

    def replace_incidents(self, incidents: List[Dict[str, object]]) -> List[Dict[str, object]]:
        self.storage.replace_incidents(incidents)
        return self.storage.list_incidents()

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

    def _deterministic_genesis_ts(self) -> float:
        base = 1_700_000_000.0
        ordered = self._all_known_nodes()
        index = ordered.index(self.config.node_id) if self.config.node_id in ordered else 0
        offset = index * 0.001
        ts = base + offset + self._genesis_counter * 0.0001
        self._genesis_counter += 1
        return ts

    def _all_known_nodes(self) -> List[str]:
        names = {self.config.node_id}
        for peer in self.config.peers:
            host = peer.split(":")[0]
            if host:
                names.add(host)
        return sorted(names)

    def _build_bias_map(self) -> Dict[str, float]:
        ordered = self._all_known_nodes()
        bias_step = 0.001
        return {name: idx * bias_step for idx, name in enumerate(ordered)}

    def _bootstrap_genesis(self, *, force: bool = False) -> None:
        if not force and self.storage.event_count() > 0:
            # ensure anchors cached for restarts
            self._anchor_ids()
            return
        payload = {"anchor": 0, "node": self.config.node_id, "genesis": True}
        ts = self._deterministic_genesis_ts()
        event = Event.create(
            cls_name=EventClass.C,
            source=self.config.node_id,
            ts_local=ts,
            vclock={},
            parents=[],
            payload=payload,
        )
        envelope = Envelope(
            event=event, path_meta=[{"node": self.config.node_id, "ts": event.ts_local}]
        )
        event.consensus_ts = ts
        self.storage.store_envelope(envelope, ts)
        if self._gossip:
            self._gossip.add_pending(event.id)
        self._anchors = [event.id]
        self._notify_viz(envelope.event, stored=True, metrics=self.metrics_snapshot())

    def _linux_ingest_state_path(self) -> str:
        configured = self.config.linux_ingest.state_path
        if configured:
            return configured
        storage_path = self.storage.path
        return str(storage_path.with_name(f"{storage_path.stem}.linux-ingest.json"))

    def _start_linux_ingest(self) -> None:
        if self._linux_ingest_task and not self._linux_ingest_task.done():
            return
        self._linux_ingest_stop.clear()
        self._linux_ingestor = LinuxAuthLogIngestor(
            config=self.config.linux_ingest,
            node_id=self.config.node_id,
            default_state_path=self._linux_ingest_state_path(),
        )
        self._linux_ingest_task = asyncio.create_task(self._linux_ingest_loop())

    async def _linux_ingest_loop(self) -> None:
        interval = max(0.5, float(self.config.linux_ingest.poll_interval_sec))
        while not self._linux_ingest_stop.is_set():
            self._linux_ingest_status.last_poll_at = utc_timestamp()
            try:
                if self._linux_ingestor is not None:
                    payloads = await asyncio.to_thread(self._linux_ingestor.poll)
                    self._linux_ingest_status.last_error = None
                    for payload in payloads:
                        emission = await self.emit_event(EventClass.A, payload)
                        if emission.stored:
                            self._linux_ingest_status.emitted_count += 1
                            self._linux_ingest_status.last_event_at = utc_timestamp()
            except Exception as exc:
                logger.exception("Linux ingestion polling failed")
                self._linux_ingest_status.last_error = str(exc)
            try:
                await asyncio.wait_for(self._linux_ingest_stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    def _prime_gossip(self) -> None:
        if not self._gossip:
            return
        events = self.storage.list_events(limit=1000)
        for event in events:
            self._gossip.add_pending(event.id)

    async def _push_initial_events(self) -> None:
        if not self._gossip or not self._session:
            return
        peers = self.list_peers()
        if not peers:
            return
        anchors = self._anchor_ids()
        envelopes: List[Envelope] = []
        for anchor in anchors:
            env = self.storage.get_envelope(anchor)
            if env:
                envelopes.append(env)
        if not envelopes:
            return
        for peer in peers:
            try:
                await self._gossip._send_to_peer(peer.address, envelopes)
            except Exception:
                logger.debug("Initial genesis push failed to %s", peer.address, exc_info=True)

    async def _fanout_critical(self, event_id: str) -> None:
        if not self._gossip:
            return
        envelope = self.storage.get_envelope(event_id)
        if not envelope:
            return
        peers = self.list_peers()
        if not peers:
            return
        results = await asyncio.gather(
            *[self._gossip._send_to_peer(peer.address, [envelope]) for peer in peers],
            return_exceptions=True,
        )
        if not all(result is True for result in results):
            self._gossip.add_pending(event_id)

    async def _broadcast_event(self, event_id: str) -> None:
        peers = self.list_peers()
        if not peers:
            return
        envelope = self.storage.get_envelope(event_id)
        if not envelope:
            return
        for peer in peers:
            try:
                ok = await self._gossip._send_to_peer(peer.address, [envelope])
                if not ok:
                    self._gossip.add_pending(event_id)
            except Exception:
                self._gossip.add_pending(event_id)

    def _schedule_fast_fanout(self, event_id: str) -> None:
        if not self._loop:
            return
        def _task() -> None:
            asyncio.create_task(self._fanout_critical(event_id))
        self._loop.call_soon_threadsafe(_task)

    def _consensus_snapshot_sync(self) -> Dict[str, object]:
        events = self.storage.all_events()
        ordered = self.consensus.total_order(events)
        ids = [event.id for event in ordered]
        joined = "::".join(ids)
        digest = hashlib.sha256(joined.encode("utf-8")).hexdigest() if ids else hashlib.sha256(b"").hexdigest()
        return {
            "node_id": self.config.node_id,
            "hash": digest,
            "event_count": len(ids),
            "latest_event": ids[-1] if ids else None,
            "generated_at": utc_timestamp(),
        }

    async def get_consensus_snapshot(self) -> Dict[str, object]:
        return await asyncio.to_thread(self._consensus_snapshot_sync)

    async def start_simulation(
        self,
        interval: float = 2.0,
        jitter: float = 0.6,
        token: Optional[str] = None,
        propagate: bool = True,
    ) -> bool:
        if self._simulation_task and not self._simulation_task.done():
            return False
        if token is None:
            token = secrets.token_hex(12)
        self._simulation_token = token
        self._simulation_stop.clear()

        async def _loop() -> None:
            keys = list(SCENARIOS.keys())
            try:
                while not self._simulation_stop.is_set():
                    burst_size = random.choices([1, 2, 3], weights=[0.62, 0.26, 0.12], k=1)[0]
                    for burst_index in range(burst_size):
                        if self._simulation_stop.is_set():
                            break
                        scenario_key = random.choice(keys)
                        bundle = scenario_payload(scenario_key)
                        await self.emit_event(bundle["class"], bundle["payload"])
                        if burst_index < burst_size - 1:
                            intra_burst_delay = random.uniform(0.08, 0.32)
                            try:
                                await asyncio.wait_for(self._simulation_stop.wait(), timeout=intra_burst_delay)
                                break
                            except asyncio.TimeoutError:
                                pass
                    base_delay = random.expovariate(1 / max(interval, 0.5))
                    delay = max(0.25, min(interval * 3.0, base_delay + random.uniform(-jitter, jitter)))
                    try:
                        await asyncio.wait_for(self._simulation_stop.wait(), timeout=delay)
                        break
                    except asyncio.TimeoutError:
                        continue
            finally:
                self._simulation_stop.set()

        self._simulation_task = asyncio.create_task(_loop())
        if propagate:
            await self._propagate_simulation(action="start", token=token, interval=interval, jitter=jitter)
        return True

    async def stop_simulation(self, *, token: Optional[str] = None, propagate: bool = True) -> bool:
        if not self._simulation_task:
            return False
        if token is None:
            token = secrets.token_hex(12)
        self._simulation_token = token
        self._simulation_stop.set()
        try:
            await self._simulation_task
        finally:
            self._simulation_task = None
        if propagate:
            await self._propagate_simulation(action="stop", token=token)
        return True

    def simulation_running(self) -> bool:
        return self._simulation_task is not None and not self._simulation_task.done()

    def demo_controls_enabled(self) -> bool:
        return not self.config.linux_ingest.enabled

    async def _consensus_monitor_loop(self) -> None:
        interval = max(1.5, self.config.gossip.period_sec * 1.5)
        while not self._consensus_stop.is_set():
            try:
                local_snapshot = await self.get_consensus_snapshot()
                peers = self.list_peers()
                if not peers:
                    await asyncio.sleep(0)
                for peer in peers:
                    peer_snapshot = await self._fetch_peer_consensus(peer.address)
                    if not peer_snapshot:
                        self._notify_consensus_status(
                            peer.address,
                            match=False,
                            local_snapshot=local_snapshot,
                            peer_snapshot=None,
                            error="unreachable",
                        )
                        continue
                    match = (
                        peer_snapshot.get("hash") == local_snapshot.get("hash")
                        and peer_snapshot.get("event_count") == local_snapshot.get("event_count")
                    )
                    self._notify_consensus_status(
                        peer.address,
                        match=match,
                        local_snapshot=local_snapshot,
                        peer_snapshot=peer_snapshot,
                        error=None,
                    )
            except Exception:
                logger.exception("Error during consensus monitoring")
            try:
                await asyncio.wait_for(self._consensus_stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    async def _fetch_peer_consensus(self, address: str) -> Optional[Dict[str, object]]:
        if not self._session:
            return None
        url = f"http://{address}/consensus/digest"
        try:
            async with self._session.get(url, timeout=5) as resp:
                if resp.status >= 200 and resp.status < 300:
                    return await resp.json()
        except Exception:
            return None
        return None

    def _notify_consensus_status(
        self,
        peer_address: Optional[str],
        *,
        match: bool,
        local_snapshot: Dict[str, object],
        peer_snapshot: Optional[Dict[str, object]],
        error: Optional[str],
    ) -> None:
        peer_key = peer_address or (peer_snapshot or {}).get("node_id") or "unknown"
        mismatch = error is not None or not match
        count = self._consensus_mismatch.get(peer_key, 0)
        if mismatch:
            count += 1
        else:
            count = 0
        self._consensus_mismatch[peer_key] = count
        pending = mismatch and count < 3

        payload: Dict[str, object] = {
            "type": "consensus_status",
            "peer": peer_address,
            "peer_node": (peer_snapshot or {}).get("node_id"),
            "match": match and not error,
            "local": {
                "hash": local_snapshot.get("hash"),
                "event_count": local_snapshot.get("event_count"),
                "latest_event": local_snapshot.get("latest_event"),
            },
            "timestamp": utc_timestamp(),
            "pending": pending,
        }
        if peer_snapshot:
            payload["peer_state"] = {
                "hash": peer_snapshot.get("hash"),
                "event_count": peer_snapshot.get("event_count"),
                "latest_event": peer_snapshot.get("latest_event"),
                "node_id": peer_snapshot.get("node_id"),
            }
        if error:
            payload["error"] = error
        self._broadcast_viz(payload)

    async def _propagate_simulation(
        self,
        *,
        action: str,
        token: str,
        interval: float | None = None,
        jitter: float | None = None,
    ) -> None:
        if not self._session:
            return
        peers = self.list_peers()
        if not peers:
            return
        payload: Dict[str, object] = {"action": action, "token": token, "propagate": False}
        if interval is not None:
            payload["interval"] = interval
        if jitter is not None:
            payload["jitter"] = jitter
        tasks = [self._send_simulation_request(peer.address, payload) for peer in peers]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_simulation_request(self, address: str, payload: Dict[str, object]) -> None:
        url = f"http://{address}/viz/simulation/control"
        try:
            async with self._session.post(url, json=payload, timeout=5) as resp:
                await resp.read()
        except Exception:
            pass

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
            "linux_ingest": self._linux_ingest_status.to_dict(),
            "demo_controls_enabled": self.demo_controls_enabled(),
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
