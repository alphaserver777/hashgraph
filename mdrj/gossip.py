"""Epidemic gossip implementation."""
from __future__ import annotations

import asyncio
import json
import random
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable, List, Optional, Sequence

import aiohttp

from .metrics import MetricsEngine
from .models import Envelope, EventClass, PeerInfo
from .prioritization import Prioritizer
from .storage import DAGStorage
from .utils import signed_request_body, utc_timestamp

PeerProvider = Callable[[], Sequence[PeerInfo]]


@dataclass
class GossipStats:
    sent: int
    peers_contacted: int
    dropped: int


class GossipEngine:
    def __init__(
        self,
        node_id: str,
        storage: DAGStorage,
        prioritizer: Prioritizer,
        metrics: MetricsEngine,
        peer_provider: PeerProvider,
        session: aiohttp.ClientSession,
        fan_out: int,
        period_sec: float,
        hmac_key: Optional[str] = None,
    ) -> None:
        self.node_id = node_id
        self.storage = storage
        self.prioritizer = prioritizer
        self.metrics = metrics
        self.peer_provider = peer_provider
        self.session = session
        self.fan_out = fan_out
        self.period_sec = period_sec
        self.hmac_key = hmac_key
        self._pending: asyncio.Queue[str] = asyncio.Queue()
        self._known_pending: set[str] = set()
        self._task: Optional[asyncio.Task] = None
        self._run_event = asyncio.Event()
        self._run_event.set()

    def add_pending(self, event_id: str) -> None:
        if event_id in self._known_pending:
            return
        self._known_pending.add(event_id)
        self._pending.put_nowait(event_id)
    def _requeue_envelopes(self, envelopes: Sequence[Envelope]) -> None:
        for env in envelopes:
            event_id = env.event.id
            if event_id in self._known_pending:
                continue
            self._known_pending.add(event_id)
            self._pending.put_nowait(event_id)

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._run_event.clear()
            await self._task
            self._task = None

    async def _loop(self) -> None:
        try:
            while self._run_event.is_set():
                await self._tick()
                await asyncio.sleep(self.period_sec)
        except asyncio.CancelledError:
            pass

    async def _collect_pending(self) -> List[Envelope]:
        envelopes: List[Envelope] = []
        while not self._pending.empty():
            event_id = await self._pending.get()
            self._known_pending.discard(event_id)
            envelope = self.storage.get_envelope(event_id)
            if not envelope:
                continue
            envelope.add_hop(self.node_id, utc_timestamp())
            envelopes.append(envelope)
        return envelopes

    async def _tick(self) -> GossipStats:
        start = time.time()
        envelopes = await self._collect_pending()
        if not envelopes:
            return GossipStats(sent=0, peers_contacted=0, dropped=0)
        required = set()
        for env in envelopes:
            if env.event.cls in (EventClass.A, EventClass.B):
                required.add(env.event.id)
                required.update(env.event.parents)
        plan = self.prioritizer.plan_batch(envelopes, required_events=required)
        if plan.deferred:
            self._requeue_envelopes(plan.deferred)
        if not plan.envelopes:
            return GossipStats(sent=0, peers_contacted=0, dropped=plan.dropped)
        self.metrics.record_batch_size(plan.total_bytes)
        peers = list(self.peer_provider())
        if not peers:
            self._requeue_envelopes(plan.envelopes)
            return GossipStats(sent=0, peers_contacted=0, dropped=plan.dropped)
        selected = random.sample(peers, min(self.fan_out, len(peers)))
        sent_total = 0
        for peer in selected:
            ok = await self._send_to_peer(peer.address, plan.envelopes)
            if ok:
                sent_total += len(plan.envelopes)
        if sent_total == 0:
            self._requeue_envelopes(plan.envelopes)
        latency = time.time() - start
        self.metrics.record_gossip_latency(latency)
        return GossipStats(sent=sent_total, peers_contacted=len(selected), dropped=plan.dropped)

    async def _send_to_peer(self, address: str, envelopes: Sequence[Envelope]) -> bool:
        url = f"http://{address}/event/batch"
        payload = []
        for env in envelopes:
            event_dict = env.event.to_dict()
            event_dict['consensus_ts'] = env.event.consensus_ts
            payload.append({
                "event": event_dict,
                "path_meta": env.path_meta,
            })
        body, headers = signed_request_body(payload, self.hmac_key)
        try:
            async with self.session.post(url, data=body, headers=headers, timeout=self.period_sec * 2) as resp:
                if resp.status != 200:
                    self.storage.upsert_peer(address, time.time(), healthy=False)
                    return False
                await resp.json()
                self.metrics.record_gossip_out_bytes(len(body))
                self.storage.upsert_peer(address, time.time(), healthy=True)
                return True
        except Exception:
            self.storage.upsert_peer(address, time.time(), healthy=False)
            return False
