"""Base classes for cross-platform security event collectors."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class CollectedEvent:
    """Single normalized event produced by a collector.

    payload must contain `event_kind` matching `mdrj/event_catalog.py`.
    The class A/B/C is resolved by the Node, not by the collector.
    """
    event_kind: str
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> Dict[str, Any]:
        merged = dict(self.payload)
        merged.setdefault("event_kind", self.event_kind)
        return merged


@dataclass(slots=True)
class CollectorStatus:
    name: str
    enabled: bool
    last_poll_at: Optional[float] = None
    last_event_at: Optional[float] = None
    last_error: Optional[str] = None
    emitted_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "last_poll_at": self.last_poll_at,
            "last_event_at": self.last_event_at,
            "last_error": self.last_error,
            "emitted_count": self.emitted_count,
        }


class BaseCollector:
    """Base for poll-based collectors.

    Subclasses override `poll()`. The orchestrator in Node.start() runs
    each collector in its own asyncio task with `poll_interval_sec`
    between calls, dispatches yielded events through `Node.emit_event`.
    """

    name: str = "base"

    def __init__(self, *, poll_interval_sec: float = 2.0, node_id: str = "", host_id: str = "") -> None:
        self.poll_interval_sec = max(0.2, float(poll_interval_sec))
        self.node_id = node_id
        self.host_id = host_id or node_id
        self.status = CollectorStatus(name=self.name, enabled=True)
        self.logger = logging.getLogger(f"mdrj.collectors.{self.name}")

    def poll(self) -> List[CollectedEvent]:
        """Return zero or more events observed since the last poll."""
        raise NotImplementedError

    def annotate(self, event: CollectedEvent) -> CollectedEvent:
        """Attach common host/node metadata to the event payload."""
        if self.host_id:
            event.payload.setdefault("host_id", self.host_id)
        if self.node_id:
            event.payload.setdefault("node_id", self.node_id)
        return event
