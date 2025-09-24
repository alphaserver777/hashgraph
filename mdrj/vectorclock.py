"""Lamport and vector clock utilities."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, Mapping


class VectorRelation(str, Enum):
    BEFORE = "before"
    AFTER = "after"
    CONCURRENT = "concurrent"
    EQUAL = "equal"


@dataclass(slots=True)
class VectorClock:
    clock: Dict[str, int] = field(default_factory=dict)

    def copy(self) -> "VectorClock":
        return VectorClock(dict(self.clock))

    def increment(self, node_id: str) -> "VectorClock":
        updated = self.copy()
        updated.clock[node_id] = updated.clock.get(node_id, 0) + 1
        return updated

    def merge(self, other: Mapping[str, int]) -> "VectorClock":
        merged = self.copy()
        for node_id, counter in other.items():
            merged.clock[node_id] = max(merged.clock.get(node_id, 0), counter)
        return merged

    def relation(self, other: Mapping[str, int]) -> VectorRelation:
        a_dominates = False
        b_dominates = False
        keys = set(self.clock) | set(other)
        for key in keys:
            a = self.clock.get(key, 0)
            b = other.get(key, 0)
            if a < b:
                b_dominates = True
            elif a > b:
                a_dominates = True
        if a_dominates and not b_dominates:
            return VectorRelation.AFTER
        if b_dominates and not a_dominates:
            return VectorRelation.BEFORE
        if not a_dominates and not b_dominates:
            return VectorRelation.EQUAL
        return VectorRelation.CONCURRENT

    def happened_before(self, other: Mapping[str, int]) -> bool:
        return self.relation(other) == VectorRelation.BEFORE

    def to_dict(self) -> Dict[str, int]:
        return dict(self.clock)

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, int]) -> "VectorClock":
        return cls(dict(mapping))

    def compare_lamport(self, other: Mapping[str, int]) -> int:
        """Compare Lamport timestamps derived from vector clock sums."""
        total_self = sum(self.clock.values())
        total_other = sum(other.values())
        if total_self < total_other:
            return -1
        if total_self > total_other:
            return 1
        return 0


def merge_all(clocks: Iterable[Mapping[str, int]]) -> VectorClock:
    merged = VectorClock()
    for clock in clocks:
        merged = merged.merge(clock)
    return merged

