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
FAME_DECISION_KIND_PENDING = "pending"
FAME_DECISION_KIND_VOTE = "vote"
FAME_DECISION_KIND_COIN_SURROGATE = "coin_surrogate"


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
    creator: str
    ts_local: float
    vclock: Dict[str, int]
    parents: List[str]
    self_parent_id: Optional[str]
    other_parent_id: Optional[str]
    payload: Dict[str, Any]
    sig: Optional[str] = None
    consensus_ts: Optional[float] = None
    lamport_ts: Optional[int] = None
    round: Optional[int] = None
    round_received: Optional[int] = None
    is_witness: bool = False
    is_famous_witness: bool = False
    fame_decided: bool = False
    fame_decision_round: Optional[int] = None
    fame_decision_kind: str = FAME_DECISION_KIND_PENDING
    fame_needs_coin: bool = False
    fame_coin_used: bool = False
    fame_coin_round: Optional[int] = None
    fame_vote_round: Optional[int] = None
    fame_vote_yes: int = 0
    fame_vote_no: int = 0

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
        creator: Optional[str] = None,
        self_parent_id: Optional[str] = None,
        other_parent_id: Optional[str] = None,
    ) -> "Event":
        parents_list = list(parents)
        if self_parent_id is None and parents_list:
            self_parent_id = parents_list[0]
        if other_parent_id is None and len(parents_list) > 1:
            other_parent_id = parents_list[1]
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
            creator=creator or source,
            ts_local=ts_local,
            vclock=dict(vclock),
            parents=parents_list,
            self_parent_id=self_parent_id,
            other_parent_id=other_parent_id,
            payload=dict(payload),
            sig=sig,
            lamport_ts=lamport_ts,
        )

    def to_record(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "cls": self.cls.value,
            "source": self.source,
            "creator": self.creator,
            "ts_local": self.ts_local,
            "vclock": canonical_json(self.vclock),
            "parents": canonical_json(self.parents),
            "self_parent_id": self.self_parent_id,
            "other_parent_id": self.other_parent_id,
            "payload": canonical_json(self.payload),
            "sig": self.sig,
            "consensus_ts": self.consensus_ts,
            "lamport_ts": self.lamport_ts,
            "round": self.round,
            "round_received": self.round_received,
            "is_witness": int(bool(self.is_witness)),
            "is_famous_witness": int(bool(self.is_famous_witness)),
            "fame_decided": int(bool(self.fame_decided)),
            "fame_decision_round": self.fame_decision_round,
            "fame_decision_kind": self.fame_decision_kind,
            "fame_needs_coin": int(bool(self.fame_needs_coin)),
            "fame_coin_used": int(bool(self.fame_coin_used)),
            "fame_coin_round": self.fame_coin_round,
            "fame_vote_round": self.fame_vote_round,
            "fame_vote_yes": self.fame_vote_yes,
            "fame_vote_no": self.fame_vote_no,
        }

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "Event":
        sig = record["sig"] if "sig" in record.keys() else None
        consensus_ts = record["consensus_ts"] if "consensus_ts" in record.keys() else None
        lamport_ts = record["lamport_ts"] if "lamport_ts" in record.keys() else None
        parents = json.loads(record["parents"])
        self_parent_id = record["self_parent_id"] if "self_parent_id" in record.keys() else None
        other_parent_id = record["other_parent_id"] if "other_parent_id" in record.keys() else None
        if self_parent_id is None and parents:
            self_parent_id = parents[0]
        if other_parent_id is None and len(parents) > 1:
            other_parent_id = parents[1]
        return cls(
            id=record["id"],
            cls=EventClass.from_str(record["cls"]),
            source=record["source"],
            creator=record["creator"] if "creator" in record.keys() and record["creator"] else record["source"],
            ts_local=float(record["ts_local"]),
            vclock=json.loads(record["vclock"]),
            parents=parents,
            self_parent_id=self_parent_id,
            other_parent_id=other_parent_id,
            payload=json.loads(record["payload"]),
            sig=sig,
            consensus_ts=consensus_ts,
            lamport_ts=lamport_ts,
            round=record["round"] if "round" in record.keys() else None,
            round_received=record["round_received"] if "round_received" in record.keys() else None,
            is_witness=bool(record["is_witness"]) if "is_witness" in record.keys() else False,
            is_famous_witness=bool(record["is_famous_witness"]) if "is_famous_witness" in record.keys() else False,
            fame_decided=bool(record["fame_decided"]) if "fame_decided" in record.keys() else False,
            fame_decision_round=record["fame_decision_round"] if "fame_decision_round" in record.keys() else None,
            fame_decision_kind=str(record["fame_decision_kind"]) if "fame_decision_kind" in record.keys() and record["fame_decision_kind"] else FAME_DECISION_KIND_PENDING,
            fame_needs_coin=bool(record["fame_needs_coin"]) if "fame_needs_coin" in record.keys() else False,
            fame_coin_used=bool(record["fame_coin_used"]) if "fame_coin_used" in record.keys() else False,
            fame_coin_round=record["fame_coin_round"] if "fame_coin_round" in record.keys() else None,
            fame_vote_round=record["fame_vote_round"] if "fame_vote_round" in record.keys() else None,
            fame_vote_yes=int(record["fame_vote_yes"]) if "fame_vote_yes" in record.keys() and record["fame_vote_yes"] is not None else 0,
            fame_vote_no=int(record["fame_vote_no"]) if "fame_vote_no" in record.keys() and record["fame_vote_no"] is not None else 0,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "cls": self.cls.value,
            "source": self.source,
            "creator": self.creator,
            "ts_local": self.ts_local,
            "vclock": dict(self.vclock),
            "parents": list(self.parents),
            "self_parent_id": self.self_parent_id,
            "other_parent_id": self.other_parent_id,
            "payload": dict(self.payload),
            "sig": self.sig,
            "consensus_ts": self.consensus_ts,
            "lamport_ts": self.lamport_ts,
            "round": self.round,
            "round_received": self.round_received,
            "is_witness": self.is_witness,
            "is_famous_witness": self.is_famous_witness,
            "fame_decided": self.fame_decided,
            "fame_decision_round": self.fame_decision_round,
            "fame_decision_kind": self.fame_decision_kind,
            "fame_needs_coin": self.fame_needs_coin,
            "fame_coin_used": self.fame_coin_used,
            "fame_coin_round": self.fame_coin_round,
            "fame_vote_round": self.fame_vote_round,
            "fame_vote_yes": self.fame_vote_yes,
            "fame_vote_no": self.fame_vote_no,
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
            creator=event_data.get("creator") or event_data["source"],
            ts_local=float(event_data["ts_local"]),
            vclock=dict(event_data["vclock"]),
            parents=list(event_data["parents"]),
            self_parent_id=event_data.get("self_parent_id") or (event_data["parents"][0] if event_data.get("parents") else None),
            other_parent_id=event_data.get("other_parent_id") or (event_data["parents"][1] if len(event_data.get("parents", [])) > 1 else None),
            payload=dict(event_data["payload"]),
            sig=event_data.get("sig"),
            consensus_ts=event_data.get("consensus_ts"),
            lamport_ts=event_data.get("lamport_ts"),
            round=event_data.get("round"),
            round_received=event_data.get("round_received"),
            is_witness=bool(event_data.get("is_witness", False)),
            is_famous_witness=bool(event_data.get("is_famous_witness", False)),
            fame_decided=bool(event_data.get("fame_decided", False)),
            fame_decision_round=event_data.get("fame_decision_round"),
            fame_decision_kind=str(event_data.get("fame_decision_kind") or FAME_DECISION_KIND_PENDING),
            fame_needs_coin=bool(event_data.get("fame_needs_coin", False)),
            fame_coin_used=bool(event_data.get("fame_coin_used", False)),
            fame_coin_round=event_data.get("fame_coin_round"),
            fame_vote_round=event_data.get("fame_vote_round"),
            fame_vote_yes=int(event_data.get("fame_vote_yes", 0) or 0),
            fame_vote_no=int(event_data.get("fame_vote_no", 0) or 0),
        )
        return cls(event=event, path_meta=[dict(hop) for hop in data.get("path_meta", [])])


PEER_APPROVAL_PENDING = "pending"
PEER_APPROVAL_APPROVED = "approved"
PEER_APPROVAL_REJECTED = "rejected"
PEER_APPROVAL_STATUSES = {PEER_APPROVAL_PENDING, PEER_APPROVAL_APPROVED, PEER_APPROVAL_REJECTED}


def normalize_approval_status(value: object) -> str:
    text = str(value or "").strip().lower()
    if text in PEER_APPROVAL_STATUSES:
        return text
    return PEER_APPROVAL_APPROVED  # default for backward compat with pre-Stage-4 configs


@dataclass(slots=True)
class PeerInfo:
    address: str
    node_id: str = ""
    last_seen: Optional[float] = None
    healthy: bool = True
    enabled: bool = True
    note: str = ""
    source: str = "runtime"
    role: str = NODE_ROLE_NODE
    is_self: bool = False
    approval_status: str = PEER_APPROVAL_APPROVED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "node_id": self.node_id,
            "last_seen": self.last_seen,
            "healthy": self.healthy,
            "enabled": self.enabled,
            "note": self.note,
            "source": self.source,
            "role": normalize_node_role(self.role),
            "is_self": self.is_self,
            "approval_status": normalize_approval_status(self.approval_status),
        }
