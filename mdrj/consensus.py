"""Consensus helpers implementing virtual voting with median timestamps."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

from .models import Envelope, Event
from .utils import median


@dataclass
class ConsensusResult:
    event_id: str
    consensus_ts: float
    contributors: int


class ConsensusEngine:
    def __init__(self, node_id: str):
        self.node_id = node_id

    def compute_timestamp(self, envelope: Envelope, arrival_ts: float) -> ConsensusResult:
        samples = envelope.consensus_candidates()
        samples.append(arrival_ts)
        consensus_ts = median(samples)
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


