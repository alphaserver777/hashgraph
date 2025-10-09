"""Runtime metrics for MDRJ-DAG."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from .config import GossipConfig
from .models import PeerInfo
from .storage import DAGStorage


@dataclass
class MetricsSnapshot:
    a_est: float
    t_gossip: float
    k_r: float
    c_mem: float
    c_net: float
    event_count: int


class MetricsEngine:
    def __init__(self, storage: DAGStorage, gossip_cfg: GossipConfig, memory_mb: int, bw_kbps: int) -> None:
        self.storage = storage
        self.gossip_cfg = gossip_cfg
        self.memory_bytes = memory_mb * 1024 * 1024
        self.bw_kbps = bw_kbps
        self._gossip_latencies: List[float] = []
        self._merge_quality = 1.0
        self._last_batch_bytes = 0
        self._peer_health: List[PeerInfo] = []
        self._quorum = 1

    def record_gossip_latency(self, latency: float) -> None:
        self._gossip_latencies.append(latency)
        if len(self._gossip_latencies) > 100:
            self._gossip_latencies.pop(0)

    def record_merge_quality(self, reconstructed_ratio: float) -> None:
        self._merge_quality = reconstructed_ratio

    def record_batch_size(self, batch_bytes: int) -> None:
        self._last_batch_bytes = batch_bytes

    def update_peer_health(self, peers: Iterable[PeerInfo], quorum: int) -> None:
        self._peer_health = list(peers)
        self._quorum = max(1, quorum)

    def reset(self) -> None:
        """Reset transient metrics after destructive operations (e.g. clearing DAG)."""
        self._gossip_latencies.clear()
        self._merge_quality = 1.0
        self._last_batch_bytes = 0

    def _availability_estimate(self) -> float:
        if not self._peer_health:
            return 1.0
        alive = sum(1 for peer in self._peer_health if peer.healthy)
        total = len(self._peer_health)
        return min(1.0, alive / max(self._quorum, 1))

    def _gossip_metric(self) -> float:
        if not self._gossip_latencies:
            return self.gossip_cfg.period_sec
        return sum(self._gossip_latencies) / len(self._gossip_latencies)

    def _network_budget_bytes(self) -> int:
        bytes_per_sec = (self.bw_kbps * 1000) // 8
        return max(1024, int(bytes_per_sec * self.gossip_cfg.period_sec))

    def snapshot(self) -> MetricsSnapshot:
        storage_bytes = self.storage.storage_usage_bytes()
        c_mem = min(1.0, storage_bytes / self.memory_bytes) if self.memory_bytes else 0.0
        budget = self._network_budget_bytes()
        c_net = min(1.0, self._last_batch_bytes / budget) if budget else 0.0
        return MetricsSnapshot(
            a_est=self._availability_estimate(),
            t_gossip=self._gossip_metric(),
            k_r=self._merge_quality,
            c_mem=c_mem,
            c_net=c_net,
            event_count=self.storage.event_count(),
        )
