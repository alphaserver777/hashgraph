"""Data models for MDRJ-DAG events and envelopes."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .utils import canonical_json, compute_event_id

NODE_ROLE_NODE = "node"
NODE_ROLE_RESPONDER = "responder"
NODE_ROLES = {NODE_ROLE_NODE, NODE_ROLE_RESPONDER}


def normalize_node_role(value: object) -> str:
    text = str(value or "").strip().lower()
    if text in NODE_ROLES:
        return text
    return NODE_ROLE_NODE


class EventClass(str, Enum):
    A = "A"
    B = "B"
    C = "C"

    @classmethod
    def from_str(cls, value: str) -> "EventClass":
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError(f"unknown event class: {value}") from exc


@dataclass(slots=True)
class NodeProfile:
    memory_mb: int
    bw_kbps: int
    cpu_quota: float
    role: str
    threat_level: str


@dataclass(slots=True)
class Event:
    id: str
    cls: EventClass
    source: str
    ts_local: float
    vclock: Dict[str, int]
    parents: List[str]
    payload: Dict[str, Any]
    sig: Optional[str] = None
    consensus_ts: Optional[float] = None
    lamport_ts: Optional[int] = None

    @classmethod
    def create(
        cls,
        *,
        cls_name: EventClass,
        source: str,
        ts_local: float,
        vclock: Mapping[str, int],
        parents: Iterable[str],
        payload: Mapping[str, Any],
        sig: Optional[str] = None,
    ) -> "Event":
        parents_list = list(parents)
        header = {
            "cls": cls_name.value,
            "source": source,
            "ts_local": ts_local,
            "vclock": dict(vclock),
            "parents": parents_list,
        }
        event_id = compute_event_id(header, payload)
        lamport_ts = sum(vclock.values())
        return cls(
            id=event_id,
            cls=cls_name,
            source=source,
            ts_local=ts_local,
            vclock=dict(vclock),
            parents=parents_list,
            payload=dict(payload),
            sig=sig,
            lamport_ts=lamport_ts,
        )

    def to_record(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "cls": self.cls.value,
            "source": self.source,
            "ts_local": self.ts_local,
            "vclock": canonical_json(self.vclock),
            "parents": canonical_json(self.parents),
            "payload": canonical_json(self.payload),
            "sig": self.sig,
            "consensus_ts": self.consensus_ts,
            "lamport_ts": self.lamport_ts,
        }

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "Event":
        sig = record["sig"] if "sig" in record.keys() else None
        consensus_ts = record["consensus_ts"] if "consensus_ts" in record.keys() else None
        lamport_ts = record["lamport_ts"] if "lamport_ts" in record.keys() else None
        return cls(
            id=record["id"],
            cls=EventClass.from_str(record["cls"]),
            source=record["source"],
            ts_local=float(record["ts_local"]),
            vclock=json.loads(record["vclock"]),
            parents=json.loads(record["parents"]),
            payload=json.loads(record["payload"]),
            sig=sig,
            consensus_ts=consensus_ts,
            lamport_ts=lamport_ts,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "cls": self.cls.value,
            "source": self.source,
            "ts_local": self.ts_local,
            "vclock": dict(self.vclock),
            "parents": list(self.parents),
            "payload": dict(self.payload),
            "sig": self.sig,
            "consensus_ts": self.consensus_ts,
            "lamport_ts": self.lamport_ts,
        }


@dataclass(slots=True)
class Envelope:
    event: Event
    path_meta: List[Dict[str, Any]] = field(default_factory=list)

    def add_hop(self, node_id: str, ts: float) -> None:
        self.path_meta.append({"node": node_id, "ts": ts})

    def consensus_candidates(self) -> List[float]:
        return [hop["ts"] for hop in self.path_meta if "ts" in hop]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "path_meta": list(self.path_meta),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Envelope":
        event_data = data["event"]
        event = Event(
            id=event_data["id"],
            cls=EventClass.from_str(event_data["cls"]),
            source=event_data["source"],
            ts_local=float(event_data["ts_local"]),
            vclock=dict(event_data["vclock"]),
            parents=list(event_data["parents"]),
            payload=dict(event_data["payload"]),
            sig=event_data.get("sig"),
            consensus_ts=event_data.get("consensus_ts"),
            lamport_ts=event_data.get("lamport_ts"),
        )
        return cls(event=event, path_meta=[dict(hop) for hop in data.get("path_meta", [])])


@dataclass(slots=True)
class PeerInfo:
    address: str
    last_seen: Optional[float] = None
    healthy: bool = True
    enabled: bool = True
    note: str = ""
    source: str = "runtime"
    role: str = NODE_ROLE_NODE
    is_self: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "last_seen": self.last_seen,
            "healthy": self.healthy,
            "enabled": self.enabled,
            "note": self.note,
            "source": self.source,
            "role": normalize_node_role(self.role),
            "is_self": self.is_self,
        }
