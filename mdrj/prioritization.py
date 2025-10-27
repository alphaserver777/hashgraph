"""Event prioritisation logic for MDRJ-DAG."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence

from .config import GossipConfig, PrioritizationConfig
from .models import Envelope, EventClass, NodeProfile
from .utils import bytes_cost

THREAT_RANK = {"LOW": 0, "ELEV": 1, "HIGH": 2}


@dataclass
class BatchPlan:
    envelopes: List[Envelope]
    total_bytes: int
    dropped: int


class Prioritizer:
    def __init__(
        self,
        profile: NodeProfile,
        gossip_cfg: GossipConfig,
        prioritization_cfg: PrioritizationConfig,
    ) -> None:
        self.profile = profile
        self.gossip_cfg = gossip_cfg
        self.prioritization_cfg = prioritization_cfg

    def _bandwidth_budget_bytes(self) -> int:
        # Convert kbps to bytes per gossip interval.
        bytes_per_sec = (self.profile.bw_kbps * 1000) // 8
        return max(1024, int(bytes_per_sec * self.gossip_cfg.period_sec))

    def _threshold_allows_b(self) -> bool:
        level_needed = THREAT_RANK.get(self.prioritization_cfg.level_threshold_B, 1)
        node_level = THREAT_RANK.get(self.profile.threat_level, 0)
        return node_level >= level_needed

    def should_relay(
        self,
        cls: EventClass,
        *,
        required_for_causality: bool = False,
        force: bool = False,
    ) -> bool:
        if force:
            return True
        if cls == EventClass.A:
            return True
        if cls == EventClass.B:
            return self._threshold_allows_b() or required_for_causality
        return required_for_causality

    def plan_batch(
        self,
        envelopes: Sequence[Envelope],
        *,
        required_events: Iterable[str] | None = None,
    ) -> BatchPlan:
        required = set(required_events or [])
        sorted_envelopes = sorted(
            envelopes,
            key=lambda env: (0 if env.event.cls == EventClass.A else 1 if env.event.cls == EventClass.B else 2, env.event.ts_local),
        )
        max_bytes = min(self._bandwidth_budget_bytes(), self.prioritization_cfg.max_batch_bytes)
        accepted: List[Envelope] = []
        total_bytes = 0
        dropped = 0
        for envelope in sorted_envelopes:
            is_genesis = isinstance(envelope.event.payload, dict) and envelope.event.payload.get("genesis")
            is_required = (
                envelope.event.id in required
                or bool(set(envelope.event.parents) & required)
                or is_genesis
            )
            if not self.should_relay(
                envelope.event.cls,
                required_for_causality=is_required,
                force=is_genesis,
            ):
                dropped += 1
                continue
            envelope_bytes = bytes_cost(envelope.to_dict())
            if total_bytes + envelope_bytes > max_bytes:
                dropped += 1
                continue
            accepted.append(envelope)
            total_bytes += envelope_bytes
            required.update(envelope.event.parents)
        return BatchPlan(envelopes=accepted, total_bytes=total_bytes, dropped=dropped)
