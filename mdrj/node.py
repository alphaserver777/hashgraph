"""Core MDRJ-DAG node implementation."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import secrets
import socket
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, List, Mapping, Optional

import aiohttp
from aiohttp import web

from .config import NodeConfig
from .collectors import (
    BaseCollector,
    LinuxAuditCollector,
    LinuxFirewallCollector,
    LinuxJournaldCollector,
    LinuxProcCollector,
)
from .consensus import ConsensusEngine, MembershipEntry
from .event_catalog import event_class_for, is_known_event_kind
from .gossip import GossipEngine
from .linux_ingest import LinuxAuthLogIngestor, LinuxIngestStatus
from .metrics import MetricsEngine
from .models import (
    NODE_ROLE_NODE,
    Envelope,
    Event,
    EventClass,
    PeerInfo,
    normalize_node_role,
)
from .prioritization import Prioritizer
from .simulation import SCENARIOS, scenario_payload
from .storage import DAGStorage
from .utils import canonical_json, hmac_signature, signed_request_body, utc_timestamp
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
        self._self_registry_address = f"self:{config.node_id}"
        self.vector_clock = VectorClock()
        self.consensus = ConsensusEngine(config.node_id)
        self.prioritizer = Prioritizer(config.profile, config.gossip, config.prioritization)
        self.metrics = MetricsEngine(
            self.storage, config.gossip, config.profile.memory_mb, config.profile.bw_kbps
        )
        self.storage.ensure_peer(
            self._self_registry_address,
            node_id=config.node_id,
            last_seen=utc_timestamp(),
            healthy=True,
            enabled=True,
            note="Текущий узел",
            source="self",
            role=normalize_node_role(config.profile.role),
        )
        for peer_address in config.peers:
            self.storage.ensure_peer(
                peer_address,
                node_id="",
                last_seen=utc_timestamp(),
                healthy=True,
                enabled=True,
                source="config",
                role=NODE_ROLE_NODE,
            )
        self._peers: Dict[str, PeerInfo] = {}
        self._reload_peers_from_storage()
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
        self._consensus_membership_snapshot: Optional[Dict[str, object]] = None
        self._collectors: List[BaseCollector] = []
        self._collector_tasks: List[asyncio.Task] = []
        self._collectors_stop = asyncio.Event()
        self._collectors_stop.set()
        self._metrics_history_task: Optional[asyncio.Task] = None
        self._metrics_history_stop = asyncio.Event()
        self._metrics_history_stop.set()
        self._metrics_history_interval = 30.0
        self._metrics_history_keep_rows = 5760  # ~48h at 30s cadence
        self._retention_task: Optional[asyncio.Task] = None
        self._retention_stop = asyncio.Event()
        self._retention_stop.set()
        self._discovery = None  # type: ignore[assignment]
        from .auth import SessionStore
        self.session_store = SessionStore()
        from .notifier import NotifierEngine
        self.notifier = NotifierEngine(config.notifier)
        from .agent_relay import AgentRelayClient
        self.agent_relay = AgentRelayClient(
            config.agent_relay,
            hmac_key=config.security.hmac_key,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._bootstrap_genesis()
        self._session = aiohttp.ClientSession()
        await self._hydrate_peer_node_ids()
        await self._ensure_consensus_membership_snapshot()
        self._gossip = GossipEngine(
            node_id=self.config.node_id,
            storage=self.storage,
            prioritizer=self.prioritizer,
            metrics=self.metrics,
            peer_provider=self.list_peers,
            session=self._session,
            fan_out=self.config.gossip.fan_out,
            period_sec=self.config.gossip.period_sec,
            hmac_key=self.config.security.hmac_key,
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
        self._start_collectors()
        self._start_metrics_history()
        if self.config.retention.enabled:
            self._start_retention()
        await self._start_discovery()

    async def stop(self) -> None:
        if self.simulation_running():
            await self.stop_simulation()
        if self._discovery is not None:
            try:
                await self._discovery.stop()
            except Exception:
                logger.exception("Error while stopping discovery")
            self._discovery = None
        if self._retention_task:
            self._retention_stop.set()
            try:
                await self._retention_task
            except Exception:
                logger.exception("Error while stopping retention loop")
            self._retention_task = None
        if self._metrics_history_task:
            self._metrics_history_stop.set()
            try:
                await self._metrics_history_task
            except Exception:
                logger.exception("Error while stopping metrics history loop")
            self._metrics_history_task = None
        if self._collector_tasks:
            self._collectors_stop.set()
            for task in self._collector_tasks:
                try:
                    await task
                except Exception:
                    logger.exception("Error while stopping collector")
            self._collector_tasks = []
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

    def list_peer_registry(self) -> List[PeerInfo]:
        return self.storage.list_peers()

    def _reload_peers_from_storage(self) -> None:
        from .models import PEER_APPROVAL_APPROVED
        active: Dict[str, PeerInfo] = {}
        for peer in self.storage.list_peers():
            if not peer.enabled or peer.is_self:
                continue
            # Gossip only with approved peers — pending/rejected peers do NOT
            # receive gossip traffic, which is the security gate for new joins.
            if peer.approval_status != PEER_APPROVAL_APPROVED:
                continue
            active[peer.address] = peer
        self._peers = active

    def current_role(self) -> str:
        for peer in self.storage.list_peers():
            if peer.is_self:
                return normalize_node_role(peer.role)
        return normalize_node_role(self.config.profile.role)

    def _current_profile_role(self) -> str:
        return self.current_role()

    def register_peer(
        self,
        address: str,
        note: str = "",
        source: str = "ui",
        role: str = NODE_ROLE_NODE,
        node_id: str = "",
        approval_status: Optional[str] = None,
    ) -> None:
        from .models import PEER_APPROVAL_APPROVED, PEER_APPROVAL_PENDING

        # Manual operator entry (source=ui or config) auto-approves;
        # auto-discovered peers (source=mdns/k8s) land as pending and wait.
        if approval_status is None:
            approval_status = (
                PEER_APPROVAL_PENDING if source in ("mdns", "k8s") else PEER_APPROVAL_APPROVED
            )
        self.storage.ensure_peer(
            address,
            node_id=node_id,
            last_seen=utc_timestamp(),
            healthy=True,
            enabled=True,
            note=note,
            source=source,
            role=role,
            approval_status=approval_status,
        )
        peer = self.storage.update_peer(
            address,
            enabled=True,
            note=note,
            last_seen=utc_timestamp(),
            healthy=True,
            role=role,
            node_id=node_id,
            approval_status=approval_status,
        )
        if peer is None:
            return
        peer.source = source
        # Only push to active gossip set if approved; pending peers are visible
        # in the registry but do not receive gossip until an admin approves them.
        if peer.approval_status == PEER_APPROVAL_APPROVED:
            self._peers[address] = peer
        self.metrics.update_peer_health(self.list_peers(), self._quorum())
        if self._gossip and peer.approval_status == PEER_APPROVAL_APPROVED:
            events = self.storage.list_events(limit=256)
            for event in events:
                self._gossip.add_pending(event.id)

    def approve_peer(self, address: str) -> Optional[PeerInfo]:
        from .models import PEER_APPROVAL_APPROVED

        peer = self.storage.update_peer(address, approval_status=PEER_APPROVAL_APPROVED)
        self._reload_peers_from_storage()
        self.metrics.update_peer_health(self.list_peers(), self._quorum())
        return peer

    def reject_peer(self, address: str) -> Optional[PeerInfo]:
        from .models import PEER_APPROVAL_REJECTED

        peer = self.storage.update_peer(address, approval_status=PEER_APPROVAL_REJECTED)
        self._reload_peers_from_storage()
        self.metrics.update_peer_health(self.list_peers(), self._quorum())
        return peer

    # ------------------------------------------------------------------
    # User management (Этап 5)
    def add_user(self, *, username: str, password: str, role: str) -> Dict[str, object]:
        from .auth import hash_password, normalize_role
        normalized = username.strip().lower()
        if not normalized:
            raise ValueError("username required")
        normalized_role = normalize_role(role)
        self.storage.upsert_user(
            username=normalized,
            password_hash=hash_password(password),
            role=normalized_role,
        )
        return {"username": normalized, "role": normalized_role}

    def remove_user(self, username: str) -> bool:
        normalized = username.strip().lower()
        removed = self.storage.delete_user(normalized)
        if removed:
            self.session_store.revoke_user(normalized)
        return removed

    def list_users(self) -> List[Dict[str, object]]:
        return self.storage.list_users()

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, object]]:
        from .auth import verify_password
        record = self.storage.get_user(username.strip().lower())
        if not record:
            return None
        if not verify_password(password, str(record["password_hash"])):
            return None
        return record

    # ------------------------------------------------------------------
    # Discovery (Этап 4)
    async def _start_discovery(self) -> None:
        from .discovery import build_discovery

        backend = build_discovery(
            config=self.config.discovery,
            node_id=self.config.node_id,
            listen=self.config.listen,
            on_peer=self._on_discovered_peer,
        )
        if backend is None:
            return
        self._discovery = backend
        try:
            await backend.start()
            logger.info("discovery started: mode=%s", self.config.discovery.mode)
        except Exception:
            logger.exception("discovery failed to start")
            self._discovery = None

    async def _on_discovered_peer(self, address: str, node_id: str, source: str) -> None:
        """Discovery callback.

        New peers normally land as `pending` and wait for an operator-issued
        `POST /peers/approve`. In trusted environments (e.g. a k3s cluster
        where every pod is ours by construction), `discovery.auto_approve_
        discovered=true` skips this gate so the cluster forms automatically.
        """
        from .models import PEER_APPROVAL_APPROVED, PEER_APPROVAL_PENDING

        # Skip if peer already known under any approval status
        for existing in self.storage.list_peers():
            if existing.address == address:
                return
        initial_status = (
            PEER_APPROVAL_APPROVED
            if self.config.discovery.auto_approve_discovered
            else PEER_APPROVAL_PENDING
        )
        try:
            await asyncio.to_thread(
                self.register_peer,
                address,
                "",  # note
                source,  # source (mdns | k8s)
                NODE_ROLE_NODE,
                node_id,
                initial_status,
            )
            logger.info(
                "discovered new peer address=%s node_id=%s source=%s status=%s",
                address,
                node_id,
                source,
                initial_status,
            )
        except Exception:
            logger.exception("failed to record discovered peer %s", address)

    def update_peer(
        self,
        address: str,
        *,
        enabled: Optional[bool] = None,
        note: Optional[str] = None,
        role: Optional[str] = None,
        node_id: Optional[str] = None,
        approval_status: Optional[str] = None,
    ) -> Optional[PeerInfo]:
        if address == self._self_registry_address:
            peer = self.storage.update_peer(
                address,
                enabled=True,
                note=note,
                role=role,
                node_id=self.config.node_id,
                last_seen=utc_timestamp(),
                healthy=True,
                approval_status=approval_status,
            )
        else:
            peer = self.storage.update_peer(
                address,
                enabled=enabled,
                note=note,
                role=role,
                node_id=node_id,
                approval_status=approval_status,
            )
        self._reload_peers_from_storage()
        self.metrics.update_peer_health(self.list_peers(), self._quorum())
        return peer

    def remove_peer(self, address: str) -> None:
        if address == self._self_registry_address:
            return
        self.storage.delete_peer(address)
        self._reload_peers_from_storage()
        self.metrics.update_peer_health(self.list_peers(), self._quorum())

    def _quorum(self) -> int:
        peers = len(self._peers) + 1
        return max(1, peers // 2 + 1)

    def _membership_entries_from_registry(self) -> List[MembershipEntry]:
        entries: List[MembershipEntry] = []
        seen = set()
        for peer in self.storage.list_peers():
            if not peer.enabled and not peer.is_self:
                continue
            node_id = (peer.node_id or "").strip()
            if not node_id:
                continue
            if node_id in seen:
                continue
            seen.add(node_id)
            entries.append(
                MembershipEntry(
                    node_id=node_id,
                    address=peer.address,
                    role=peer.role,
                    is_self=peer.is_self,
                )
            )
        if self.config.node_id not in seen:
            entries.append(
                MembershipEntry(
                    node_id=self.config.node_id,
                    address=self._self_registry_address,
                    role=self.current_role(),
                    is_self=True,
                )
            )
        return sorted(entries, key=lambda item: item.node_id)

    async def _hydrate_peer_node_ids(self) -> None:
        if not self._session:
            return
        peers = [peer for peer in self.storage.list_peers() if not peer.is_self and peer.enabled]
        for peer in peers:
            if peer.node_id:
                continue
            try:
                async with self._session.get(f"http://{peer.address}/status", timeout=5) as resp:
                    if resp.status < 200 or resp.status >= 300:
                        continue
                    payload = await resp.json()
            except Exception:
                continue
            remote_node_id = str(payload.get("node_id") or "").strip()
            if remote_node_id:
                self.storage.update_peer(
                    peer.address,
                    node_id=remote_node_id,
                    last_seen=utc_timestamp(),
                    healthy=True,
                )
        self._reload_peers_from_storage()

    async def _ensure_consensus_membership_snapshot(self) -> None:
        snapshot = self.storage.get_consensus_membership_snapshot()
        if snapshot:
            self._consensus_membership_snapshot = snapshot
            return
        await self.reconfigure_consensus_membership()

    def active_consensus_membership(self) -> Dict[str, object]:
        snapshot = self._consensus_membership_snapshot or self.storage.get_consensus_membership_snapshot()
        if snapshot:
            self._consensus_membership_snapshot = snapshot
            return snapshot
        entries = self._membership_entries_from_registry()
        snapshot = self.consensus.membership_snapshot(epoch=1, members=entries)
        self.storage.save_consensus_membership_snapshot(snapshot)
        self._consensus_membership_snapshot = snapshot
        return snapshot

    async def reconfigure_consensus_membership(self) -> Dict[str, object]:
        await self._hydrate_peer_node_ids()
        previous = self.storage.get_consensus_membership_snapshot()
        epoch = int((previous or {}).get("epoch") or 0) + 1
        entries = self._membership_entries_from_registry()
        snapshot = self.consensus.membership_snapshot(epoch=epoch, members=entries)
        self.storage.save_consensus_membership_snapshot(snapshot)
        self._consensus_membership_snapshot = snapshot
        self._recompute_consensus()
        return snapshot

    def _recompute_consensus(self) -> None:
        events = self.storage.all_events()
        if not events:
            return
        path_meta_by_event = {}
        for event in events:
            envelope = self.storage.get_envelope(event.id)
            path_meta_by_event[event.id] = envelope.path_meta if envelope else []
        snapshot = self.active_consensus_membership()
        membership = [
            MembershipEntry(
                node_id=str(item.get("node_id") or "").strip(),
                address=str(item.get("address") or ""),
                role=str(item.get("role") or NODE_ROLE_NODE),
                is_self=bool(item.get("is_self", False)),
            )
            for item in snapshot.get("members", [])
            if str(item.get("node_id") or "").strip()
        ]
        order_ids = self.storage.toposort()
        by_id = {event.id: event for event in events}
        ordered_events = [by_id[event_id] for event_id in order_ids if event_id in by_id]
        try:
            states = self.consensus.recompute(
                ordered_events,
                membership,
                path_meta_by_event=path_meta_by_event,
            )
        except Exception:
            logger.exception("Consensus recompute failed; keeping event ingest path alive")
            return
        self.storage.replace_consensus_state(
            [
                {
                    "event_id": state.event_id,
                    "creator": state.creator,
                    "self_parent_id": state.self_parent_id,
                    "other_parent_id": state.other_parent_id,
                    "round": state.round,
                    "round_received": state.round_received,
                    "is_witness": state.is_witness,
                    "is_famous_witness": state.is_famous_witness,
                    "fame_decided": state.fame_decided,
                    "fame_decision_round": state.fame_decision_round,
                    "fame_decision_kind": state.fame_decision_kind,
                    "fame_needs_coin": state.fame_needs_coin,
                    "fame_coin_used": state.fame_coin_used,
                    "fame_coin_round": state.fame_coin_round,
                    "fame_vote_round": state.fame_vote_round,
                    "fame_vote_yes": state.fame_vote_yes,
                    "fame_vote_no": state.fame_vote_no,
                    "consensus_ts": state.consensus_ts,
                }
                for state in states
            ]
        )

    # ------------------------------------------------------------------
    # Events
    async def emit_event(self, cls_name: EventClass, payload: Mapping[str, object]) -> EventEmission:
        emit_start = time.perf_counter()
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
            creator=self.config.node_id,
            self_parent_id=parents[0] if parents else None,
            other_parent_id=parents[1] if len(parents) > 1 else None,
            payload=payload,
            sig=self._sign_payload(payload) if self.config.security.hmac_key else None,
        )
        envelope = Envelope(event=event, path_meta=[{"node": self.config.node_id, "ts": ts}])
        stored = self._persist_envelope(envelope)
        self.metrics.record_emit_to_consensus_latency(time.perf_counter() - emit_start)
        self.vector_clock = local_clock.merge(event.vclock)
        self.metrics.update_peer_health(self.list_peers(), self._quorum())
        if stored and event.cls in (EventClass.A, EventClass.B):
            await self._broadcast_event(event.id)
        if stored and self.notifier.should_trigger(event.cls.value):
            asyncio.create_task(self._notify_event(event))
        return EventEmission(event=event, stored=stored)

    async def _notify_event(self, event: Event) -> None:
        from .notifier import NotificationPayload

        try:
            await self.notifier.dispatch(
                NotificationPayload(
                    event_id=event.id,
                    event_kind=str(event.payload.get("event_kind", "")) or event.cls.value,
                    cls=event.cls.value,
                    creator=event.creator,
                    payload=dict(event.payload),
                    ts=utc_timestamp(),
                )
            )
        except Exception:
            logger.exception("notifier dispatch failed")

    def _persist_envelope(self, envelope: Envelope) -> bool:
        stored = self.storage.store_envelope(envelope, envelope.event.consensus_ts)
        self._recompute_consensus()
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
        self._recompute_consensus()
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

    def _known_node_identities(self) -> List[Dict[str, object]]:
        identities: List[Dict[str, object]] = []
        listen_host, listen_port = self.config.listen.split(":")
        identities.append(
            {
                "subject_node_id": self.config.node_id,
                "host_id": self.config.linux_ingest.host_id or self.config.node_id,
                "runtime_hostname": socket.gethostname(),
                "listen": self.config.listen,
                "listen_host": listen_host,
                "listen_port": int(listen_port),
                "identity_scope": "self",
            }
        )
        for peer in self.config.peers:
            peer_host, _, peer_port = peer.partition(":")
            identities.append(
                {
                    "subject_node_id": peer_host or peer,
                    "configured_peer_address": peer,
                    "configured_peer_host": peer_host or peer,
                    "configured_peer_port": int(peer_port) if peer_port.isdigit() else peer_port,
                    "identity_scope": "known_peer",
                }
            )
        return identities

    def _bootstrap_genesis(self, *, force: bool = False) -> None:
        if not force and self.storage.event_count() > 0:
            # ensure anchors cached for restarts
            self._anchor_ids()
            return
        anchors: List[str] = []
        for index, identity in enumerate(self._known_node_identities()):
            payload = {
                "anchor": index,
                "node": self.config.node_id,
                "genesis": True,
                "genesis_kind": "node_identity",
                **identity,
            }
            ts = self._deterministic_genesis_ts()
            event = Event.create(
                cls_name=EventClass.C,
                source=self.config.node_id,
                creator=self.config.node_id,
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
            anchors.append(event.id)
            self._notify_viz(envelope.event, stored=True, metrics=self.metrics_snapshot())
        self._anchors = anchors

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

    # ------------------------------------------------------------------
    # Cross-platform collectors orchestration
    def _build_collectors(self) -> List[BaseCollector]:
        cfg = self.config.collectors
        node_id = self.config.node_id
        host_id = self.config.linux_ingest.host_id or node_id
        built: List[BaseCollector] = []
        if cfg.journald.enabled:
            built.append(LinuxJournaldCollector(config=cfg.journald, node_id=node_id, host_id=host_id))
        if cfg.audit.enabled:
            built.append(LinuxAuditCollector(config=cfg.audit, node_id=node_id, host_id=host_id))
        if cfg.firewall.enabled:
            built.append(LinuxFirewallCollector(config=cfg.firewall, node_id=node_id, host_id=host_id))
        if cfg.proc.enabled:
            built.append(LinuxProcCollector(config=cfg.proc, node_id=node_id, host_id=host_id))
        return built

    def _start_collectors(self) -> None:
        collectors = self._build_collectors()
        if not collectors:
            return
        self._collectors = collectors
        self._collectors_stop.clear()
        for collector in collectors:
            self._collector_tasks.append(asyncio.create_task(self._run_collector_loop(collector)))

    async def _run_collector_loop(self, collector: BaseCollector) -> None:
        interval = max(0.2, float(collector.poll_interval_sec))
        while not self._collectors_stop.is_set():
            try:
                events = await asyncio.to_thread(collector.poll)
                for event in events:
                    if not is_known_event_kind(event.event_kind):
                        logger.warning(
                            "Collector %s emitted unknown event_kind %s; skipped",
                            collector.name,
                            event.event_kind,
                        )
                        continue
                    cls = event_class_for(event.event_kind)
                    payload = event.to_payload()
                    if self.config.agent_relay.enabled:
                        # Scenario 1 (A1): forward to centralized collector.
                        # No local DAG, no gossip, no checkpoint.
                        await self.agent_relay.send(
                            event_kind=event.event_kind, cls=cls.value, payload=payload
                        )
                    else:
                        # Scenario 2 (A4): emit into local DAG, gossip will replicate.
                        await self.emit_event(cls, payload)
            except Exception:
                logger.exception("Collector %s polling failed", collector.name)
            try:
                await asyncio.wait_for(self._collectors_stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    def list_collector_status(self) -> List[Dict[str, object]]:
        return [collector.status.to_dict() for collector in self._collectors]

    # ------------------------------------------------------------------
    # Metrics history (Этап 2)
    def _start_metrics_history(self) -> None:
        if self._metrics_history_task and not self._metrics_history_task.done():
            return
        self._metrics_history_stop.clear()
        self._metrics_history_task = asyncio.create_task(self._metrics_history_loop())

    async def _metrics_history_loop(self) -> None:
        interval = max(0.05, float(self._metrics_history_interval))
        while not self._metrics_history_stop.is_set():
            try:
                snapshot = self.metrics_snapshot()
                payload = canonical_json(snapshot)
                await asyncio.to_thread(
                    self.storage.append_metrics_snapshot, utc_timestamp(), payload
                )
                # Periodic pruning to bound metrics_history rows
                await asyncio.to_thread(
                    lambda: self.storage.prune_metrics_history(keep_last=self._metrics_history_keep_rows)
                )
            except Exception:
                logger.exception("metrics_history loop failure")
            try:
                await asyncio.wait_for(self._metrics_history_stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    def list_metrics_history(self, *, limit: int = 1000, since_ts: float = 0.0) -> List[Dict[str, object]]:
        return self.storage.list_metrics_history(limit=limit, since_ts=since_ts)

    # ------------------------------------------------------------------
    # Checkpoints (Этап 3.a): propose, ingest, verify
    def _events_up_to_round_received(self, target_round: int) -> List[Event]:
        events = self.storage.all_events()
        return [event for event in events if event.round_received is not None and event.round_received <= target_round]

    def _membership_node_ids(self) -> List[str]:
        snapshot = self.active_consensus_membership()
        return [str(m.get("node_id") or "").strip() for m in snapshot.get("members", []) if m.get("node_id")]

    def _membership_snapshot_hash(self) -> str:
        snapshot = self.active_consensus_membership()
        return str(snapshot.get("membership_snapshot_hash") or "")

    def propose_local_checkpoint(self, target_round: int) -> Dict[str, object]:
        """Propose a checkpoint at target_round_received and add the local
        signature to a pending checkpoint in the DB. Returns the proposal so
        the caller can broadcast it to peers."""
        from .checkpoint import CheckpointProposal, compute_merkle_root, sign_proposal

        if target_round < 0:
            raise ValueError("target_round must be non-negative")
        hmac_key = self.config.security.hmac_key
        if not hmac_key:
            raise ValueError("security.hmac_key must be set to propose checkpoints")
        events = self._events_up_to_round_received(target_round)
        if not events:
            raise ValueError(f"no events with round_received <= {target_round}")
        merkle = compute_merkle_root(events)
        members_hash = self._membership_snapshot_hash()
        proposal = CheckpointProposal(
            round_received=int(target_round),
            merkle_root=merkle,
            members_snapshot_hash=members_hash,
            proposer_node_id=self.config.node_id,
        )
        proposal.signature = sign_proposal(proposal, hmac_key)
        self._record_proposal_signature(proposal)
        return proposal.to_dict()

    def _record_proposal_signature(self, proposal) -> Dict[str, object]:
        from .checkpoint import is_quorum_reached

        existing = self.storage.get_checkpoint(proposal.round_received)
        signatures: Dict[str, str] = dict(existing["signatures"]) if existing else {}
        if existing and existing["merkle_root"] != proposal.merkle_root:
            logger.warning(
                "Checkpoint at round %s has mismatching merkle_root (local=%s incoming=%s) — ignoring proposal",
                proposal.round_received,
                existing["merkle_root"],
                proposal.merkle_root,
            )
            return existing
        signatures[proposal.proposer_node_id] = proposal.signature
        members = self._membership_node_ids()
        if is_quorum_reached(signatures, members):
            status = "confirmed"
            confirmed_at = utc_timestamp()
        else:
            status = existing["status"] if existing and existing["status"] == "confirmed" else "pending"
            confirmed_at = existing["confirmed_at"] if existing and existing["confirmed_at"] else None
        self.storage.upsert_checkpoint(
            round_received=proposal.round_received,
            merkle_root=proposal.merkle_root,
            members_snapshot_hash=proposal.members_snapshot_hash,
            signatures=signatures,
            status=status,
            confirmed_at=confirmed_at,
        )
        return self.storage.get_checkpoint(proposal.round_received) or {}

    def ingest_checkpoint_proposal(self, payload: Dict[str, object]) -> Dict[str, object]:
        """Accept a proposal from another peer, verify HMAC, add to local
        checkpoint state."""
        from .checkpoint import CheckpointProposal, verify_proposal_signature

        proposal = CheckpointProposal.from_dict(payload)
        hmac_key = self.config.security.hmac_key
        if hmac_key and proposal.signature:
            if not verify_proposal_signature(proposal, proposal.signature, hmac_key):
                raise ValueError("invalid checkpoint signature")
        return self._record_proposal_signature(proposal)

    def list_checkpoints(self, *, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, object]]:
        return self.storage.list_checkpoints(status=status, limit=limit)

    # ------------------------------------------------------------------
    # Retention loop (Этап 3.b)
    def _start_retention(self) -> None:
        if self._retention_task and not self._retention_task.done():
            return
        self._retention_stop.clear()
        self._retention_task = asyncio.create_task(self._retention_loop())

    async def _retention_loop(self) -> None:
        interval = max(5.0, float(self.config.retention.poll_interval_sec))
        while not self._retention_stop.is_set():
            try:
                await asyncio.to_thread(self.run_retention_once)
            except Exception:
                logger.exception("retention loop failure")
            try:
                await asyncio.wait_for(self._retention_stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    def run_retention_once(self) -> Dict[str, object]:
        """Single retention pass: prune events covered by latest confirmed checkpoint."""
        cfg = self.config.retention
        if not cfg.enabled:
            return {"status": "disabled", "pruned": 0}
        checkpoint = self.storage.latest_confirmed_checkpoint()
        if not checkpoint:
            return {"status": "no_confirmed_checkpoint", "pruned": 0}
        max_age_sec = max(0.0, cfg.max_age_days * 86400.0)
        pruned = self.storage.prune_under_checkpoint(
            confirmed_round=int(checkpoint["round_received"]),
            max_age_seconds=max_age_sec,
            keep_class_a=cfg.keep_class_a,
            now=utc_timestamp(),
        )
        if cfg.archive_path and pruned:
            self._write_archive_chunk(cfg.archive_path, pruned, checkpoint)
        return {
            "status": "ok",
            "pruned": len(pruned),
            "checkpoint_round": int(checkpoint["round_received"]),
        }

    def _write_archive_chunk(self, path: str, records: List[Dict[str, object]], checkpoint: Dict[str, object]) -> None:
        import json
        from pathlib import Path

        archive = Path(path)
        archive.parent.mkdir(parents=True, exist_ok=True)
        header = {
            "checkpoint_round": int(checkpoint["round_received"]),
            "merkle_root": checkpoint["merkle_root"],
            "members_snapshot_hash": checkpoint["members_snapshot_hash"],
            "exported_at": utc_timestamp(),
        }
        with archive.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps({"_archive_header": header}, ensure_ascii=False) + "\n")
            for record in records:
                fp.write(json.dumps(record, ensure_ascii=False) + "\n")

    def verify_checkpoint(self, round_received: int) -> Dict[str, object]:
        """Recompute merkle from local events and compare against checkpoint."""
        from .checkpoint import CheckpointVerificationReport, compute_merkle_root

        checkpoint = self.storage.get_checkpoint(round_received)
        if not checkpoint:
            raise KeyError(f"no checkpoint at round_received={round_received}")
        events = self._events_up_to_round_received(round_received)
        local_merkle = compute_merkle_root(events) if events else ""
        matches = bool(local_merkle) and local_merkle == checkpoint["merkle_root"]
        report = CheckpointVerificationReport(
            matches_merkle=matches,
            local_merkle_root=local_merkle,
            confirmed_merkle_root=checkpoint["merkle_root"],
            checkpoint_round=round_received,
            has_tamper_evidence=not matches and checkpoint["status"] == "confirmed",
        )
        if checkpoint["status"] != "confirmed":
            report.notes.append("checkpoint is not yet confirmed")
        if not events:
            report.notes.append("no local events at or before target round")
        return report.to_dict()

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
        membership = self.active_consensus_membership()
        return {
            "node_id": self.config.node_id,
            "hash": digest,
            "event_count": len(ids),
            "latest_event": ids[-1] if ids else None,
            "consensus_epoch": membership.get("epoch"),
            "consensus_membership_size": membership.get("membership_size"),
            "membership_snapshot_hash": membership.get("membership_snapshot_hash"),
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
                            mismatch_reasons=["unreachable"],
                        )
                        continue
                    mismatch_reasons = self._consensus_mismatch_reasons(local_snapshot, peer_snapshot)
                    match = (
                        peer_snapshot.get("hash") == local_snapshot.get("hash")
                        and peer_snapshot.get("event_count") == local_snapshot.get("event_count")
                        and peer_snapshot.get("membership_snapshot_hash") == local_snapshot.get("membership_snapshot_hash")
                        and peer_snapshot.get("consensus_epoch") == local_snapshot.get("consensus_epoch")
                    )
                    self._notify_consensus_status(
                        peer.address,
                        match=match,
                        local_snapshot=local_snapshot,
                        peer_snapshot=peer_snapshot,
                        error=None,
                        mismatch_reasons=mismatch_reasons,
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
                    payload = await resp.json()
                    peer_node_id = str(payload.get("node_id") or "").strip()
                    if peer_node_id:
                        self.storage.update_peer(
                            address,
                            node_id=peer_node_id,
                            last_seen=utc_timestamp(),
                            healthy=True,
                        )
                    return payload
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
        mismatch_reasons: Optional[List[str]] = None,
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
                "consensus_epoch": local_snapshot.get("consensus_epoch"),
                "membership_snapshot_hash": local_snapshot.get("membership_snapshot_hash"),
            },
            "timestamp": utc_timestamp(),
            "pending": pending,
            "mismatch_reasons": list(mismatch_reasons or []),
        }
        if peer_snapshot:
            payload["peer_state"] = {
                "hash": peer_snapshot.get("hash"),
                "event_count": peer_snapshot.get("event_count"),
                "latest_event": peer_snapshot.get("latest_event"),
                "node_id": peer_snapshot.get("node_id"),
                "consensus_epoch": peer_snapshot.get("consensus_epoch"),
                "membership_snapshot_hash": peer_snapshot.get("membership_snapshot_hash"),
            }
        if error:
            payload["error"] = error
        self._broadcast_viz(payload)

    def _consensus_mismatch_reasons(
        self,
        local_snapshot: Dict[str, object],
        peer_snapshot: Dict[str, object],
    ) -> List[str]:
        reasons: List[str] = []
        if peer_snapshot.get("event_count") != local_snapshot.get("event_count"):
            reasons.append("event_count")
        if peer_snapshot.get("hash") != local_snapshot.get("hash"):
            reasons.append("hash")
        if peer_snapshot.get("consensus_epoch") != local_snapshot.get("consensus_epoch"):
            reasons.append("epoch")
        if peer_snapshot.get("membership_snapshot_hash") != local_snapshot.get("membership_snapshot_hash"):
            reasons.append("membership")
        return reasons

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
        body, headers = signed_request_body(payload, self.config.security.hmac_key)
        try:
            async with self._session.post(url, data=body, headers=headers, timeout=5) as resp:
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
        body, headers = signed_request_body(payload, self.config.security.hmac_key)
        try:
            async with self._session.post(url, data=body, headers=headers, timeout=5) as resp:
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
        membership = self.active_consensus_membership()
        mismatch_peers = sorted(peer for peer, count in self._consensus_mismatch.items() if count >= 3)
        pending_peers = sorted(peer for peer, count in self._consensus_mismatch.items() if 0 < count < 3)
        if mismatch_peers:
            consensus_health = "mismatch"
        elif pending_peers:
            consensus_health = "pending"
        else:
            consensus_health = "ok"
        return {
            "node_id": self.config.node_id,
            "state": self.state.value,
            "peers": [peer.to_dict() for peer in self.list_peers()],
            "profile": {
                "role": self._current_profile_role(),
                "memory_mb": self.config.profile.memory_mb,
                "bw_kbps": self.config.profile.bw_kbps,
                "threat_level": self.config.profile.threat_level,
            },
            "consensus_epoch": membership.get("epoch"),
            "consensus_membership_size": membership.get("membership_size"),
            "membership_snapshot_hash": membership.get("membership_snapshot_hash"),
            "consensus_health": consensus_health,
            "consensus_mismatch_peers": mismatch_peers,
            "consensus_pending_peers": pending_peers,
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
            "rss_bytes": snap.rss_bytes,
            "cpu_percent": snap.cpu_percent,
            "db_size_bytes": snap.db_size_bytes,
            "gossip_bytes_in_total": snap.gossip_bytes_in_total,
            "gossip_bytes_out_total": snap.gossip_bytes_out_total,
            "bytes_per_event": snap.bytes_per_event,
            "emit_to_consensus_latency_p50_ms": snap.emit_to_consensus_latency_p50_ms,
            "emit_to_consensus_latency_p95_ms": snap.emit_to_consensus_latency_p95_ms,
        }
