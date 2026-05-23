"""Runtime metrics for MDRJ-DAG."""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Iterable, List, Optional

try:
    import psutil  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - psutil is a runtime dependency
    psutil = None  # type: ignore[assignment]

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
    # Этап 2 ресурсные метрики:
    rss_bytes: int = 0
    cpu_percent: float = 0.0
    db_size_bytes: int = 0
    gossip_bytes_in_total: int = 0
    gossip_bytes_out_total: int = 0
    bytes_per_event: float = 0.0
    emit_to_consensus_latency_p50_ms: float = 0.0
    emit_to_consensus_latency_p95_ms: float = 0.0

    def to_dict(self):
        return asdict(self)


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
        # Этап 2:
        self._gossip_bytes_in_total = 0
        self._gossip_bytes_out_total = 0
        self._emit_to_consensus_latencies: List[float] = []  # seconds
        self._process: Optional[object] = None
        if psutil is not None:
            try:
                self._process = psutil.Process(os.getpid())
                # Prime cpu_percent — первый вызов всегда 0
                self._process.cpu_percent(interval=None)
            except Exception:
                self._process = None

    def record_gossip_latency(self, latency: float) -> None:
        self._gossip_latencies.append(latency)
        if len(self._gossip_latencies) > 100:
            self._gossip_latencies.pop(0)

    def record_merge_quality(self, reconstructed_ratio: float) -> None:
        self._merge_quality = reconstructed_ratio

    def record_batch_size(self, batch_bytes: int) -> None:
        self._last_batch_bytes = batch_bytes

    def record_gossip_in_bytes(self, count: int) -> None:
        self._gossip_bytes_in_total += int(count)

    def record_gossip_out_bytes(self, count: int) -> None:
        self._gossip_bytes_out_total += int(count)

    def record_emit_to_consensus_latency(self, latency_sec: float) -> None:
        self._emit_to_consensus_latencies.append(float(latency_sec))
        if len(self._emit_to_consensus_latencies) > 1000:
            self._emit_to_consensus_latencies.pop(0)

    def update_peer_health(self, peers: Iterable[PeerInfo], quorum: int) -> None:
        self._peer_health = list(peers)
        self._quorum = max(1, quorum)

    def reset(self) -> None:
        """Reset transient metrics after destructive operations (e.g. clearing DAG)."""
        self._gossip_latencies.clear()
        self._merge_quality = 1.0
        self._last_batch_bytes = 0
        self._gossip_bytes_in_total = 0
        self._gossip_bytes_out_total = 0
        self._emit_to_consensus_latencies.clear()

    def _availability_estimate(self) -> float:
        if not self._peer_health:
            return 1.0
        alive = sum(1 for peer in self._peer_health if peer.healthy)
        return min(1.0, alive / max(self._quorum, 1))

    def _gossip_metric(self) -> float:
        if not self._gossip_latencies:
            return self.gossip_cfg.period_sec
        return sum(self._gossip_latencies) / len(self._gossip_latencies)

    def _network_budget_bytes(self) -> int:
        bytes_per_sec = (self.bw_kbps * 1000) // 8
        return max(1024, int(bytes_per_sec * self.gossip_cfg.period_sec))

    def _percentile(self, values: List[float], pct: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        if len(ordered) == 1:
            return ordered[0]
        index = max(0, min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1)))))
        return ordered[index]

    def _read_process_metrics(self) -> tuple[int, float]:
        if self._process is None:
            return 0, 0.0
        try:
            rss = int(self._process.memory_info().rss)  # type: ignore[attr-defined]
            cpu = float(self._process.cpu_percent(interval=None))  # type: ignore[attr-defined]
            return rss, cpu
        except Exception:
            return 0, 0.0

    def snapshot(self) -> MetricsSnapshot:
        storage_bytes = self.storage.storage_usage_bytes()
        c_mem = min(1.0, storage_bytes / self.memory_bytes) if self.memory_bytes else 0.0
        budget = self._network_budget_bytes()
        c_net = min(1.0, self._last_batch_bytes / budget) if budget else 0.0
        event_count = self.storage.event_count()
        db_size = self.storage.db_size_bytes()
        rss, cpu = self._read_process_metrics()
        total_gossip_bytes = self._gossip_bytes_in_total + self._gossip_bytes_out_total
        bytes_per_event = float(total_gossip_bytes) / float(event_count) if event_count > 0 else 0.0
        latencies_ms = [lat * 1000 for lat in self._emit_to_consensus_latencies]
        return MetricsSnapshot(
            a_est=self._availability_estimate(),
            t_gossip=self._gossip_metric(),
            k_r=self._merge_quality,
            c_mem=c_mem,
            c_net=c_net,
            event_count=event_count,
            rss_bytes=rss,
            cpu_percent=cpu,
            db_size_bytes=db_size,
            gossip_bytes_in_total=self._gossip_bytes_in_total,
            gossip_bytes_out_total=self._gossip_bytes_out_total,
            bytes_per_event=bytes_per_event,
            emit_to_consensus_latency_p50_ms=self._percentile(latencies_ms, 50),
            emit_to_consensus_latency_p95_ms=self._percentile(latencies_ms, 95),
        )
