"""Consensus helpers implementing virtual voting with median timestamps."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable, List, Sequence, Tuple

from .models import Envelope, Event
from .utils import median


@dataclass
class ConsensusResult:
    event_id: str
    consensus_ts: float
    contributors: int


class ConsensusEngine:
    def __init__(self, node_id: str, bias_map: Optional[Dict[str, float]] = None):
        self.node_id = node_id
        self._bias_map = bias_map or {}

    def compute_timestamp(self, envelope: Envelope, arrival_ts: float) -> ConsensusResult:
        if envelope.event.consensus_ts is not None:
            return ConsensusResult(
                event_id=envelope.event.id,
                consensus_ts=envelope.event.consensus_ts,
                contributors=len(envelope.consensus_candidates()),
            )
        lamport = envelope.event.lamport_ts
        if lamport is None:
            lamport = sum(int(counter) for counter in envelope.event.vclock.values())
        bias = self._source_bias(envelope.event.source)
        base_ts = float(lamport) + bias
        samples = envelope.consensus_candidates()
        if samples:
            bound = max(samples)
            if bound > base_ts:
                base_ts = bound + bias * 1e-6
        consensus_ts = base_ts
        envelope.event.consensus_ts = consensus_ts
        return ConsensusResult(
            event_id=envelope.event.id,
            consensus_ts=consensus_ts,
            contributors=len(samples),
        )

    @staticmethod
    def total_order(events: Sequence[Event]) -> List[Event]:
        decorated = [
            (event.consensus_ts if event.consensus_ts is not None else float("inf"), event.id, event)
            for event in events
        ]
        decorated.sort()
        return [ev for _, _, ev in decorated]

    def _source_bias(self, source: str) -> float:
        if source in self._bias_map:
            return self._bias_map[source]
        if not source:
            return 0.0
        digest = hashlib.sha256(source.encode("utf-8")).digest()
        value = int.from_bytes(digest[:6], "big")  # use 48 bits
        return (value % 1_000_000) / 1_000_000.0
