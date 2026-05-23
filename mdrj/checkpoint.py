"""Checkpoint mechanism for tamper-proof rotation of the distributed registry.

A checkpoint freezes the state of the registry up to a target
`round_received`. It carries:
  - merkle_root: deterministic SHA-256 over consensus-ordered event hashes
    with `round_received <= target`
  - members_snapshot_hash: link to the consensus membership snapshot under
    which the checkpoint was produced
  - signatures: map node_id → hex HMAC-SHA256 of the canonical proposal
    body, signed with the shared `security.hmac_key`

A checkpoint becomes `confirmed` when it accumulates signatures from
≥2/3 of the membership snapshot members. Only then is it considered an
anchor under which historical events may be pruned to event_skeletons.

Production iteration of this prototype should swap HMAC for per-node
Ed25519 keypairs (see open question in /home/admsys/.claude/plans/quirky-whistling-clover.md).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional

from .models import Event
from .utils import canonical_json


@dataclass
class CheckpointProposal:
    round_received: int
    merkle_root: str
    members_snapshot_hash: str
    proposer_node_id: str
    signature: str = ""

    def canonical_body(self) -> Dict[str, object]:
        return {
            "round_received": int(self.round_received),
            "merkle_root": self.merkle_root,
            "members_snapshot_hash": self.members_snapshot_hash,
        }

    def to_dict(self) -> Dict[str, object]:
        return {
            **self.canonical_body(),
            "proposer_node_id": self.proposer_node_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "CheckpointProposal":
        return cls(
            round_received=int(data["round_received"]),
            merkle_root=str(data["merkle_root"]),
            members_snapshot_hash=str(data["members_snapshot_hash"]),
            proposer_node_id=str(data.get("proposer_node_id", "")),
            signature=str(data.get("signature", "")),
        )


def _event_leaf_hash(event: Event) -> str:
    body = {
        "id": event.id,
        "cls": event.cls.value,
        "creator": event.creator,
        "parents": list(event.parents),
        "consensus_ts": event.consensus_ts,
        "round_received": event.round_received,
        "payload_hash": hashlib.sha256(canonical_json(event.payload).encode()).hexdigest(),
    }
    return hashlib.sha256(canonical_json(body).encode()).hexdigest()


def compute_merkle_root(events: Iterable[Event]) -> str:
    """Deterministic Merkle root over events ordered by (round_received, id).

    Uses a flat SHA-256 over the concatenation of leaf hashes. This is not a
    classical Merkle tree, but it gives the same tamper-evidence guarantee for
    a fixed event set and is much simpler to verify. A future iteration may
    replace this with a proper binary tree once the surrounding plumbing is
    stable.
    """
    leaves: List[str] = []
    for event in sorted(
        events,
        key=lambda e: (
            -1 if e.round_received is None else int(e.round_received),
            e.id,
        ),
    ):
        leaves.append(_event_leaf_hash(event))
    digest = hashlib.sha256()
    for leaf in leaves:
        digest.update(leaf.encode())
    return digest.hexdigest()


def sign_proposal(proposal: CheckpointProposal, hmac_key: str) -> str:
    body = canonical_json(proposal.canonical_body()).encode()
    return _hmac.new(hmac_key.encode(), body, hashlib.sha256).hexdigest()


def verify_proposal_signature(
    proposal: CheckpointProposal, signature: str, hmac_key: str
) -> bool:
    expected = sign_proposal(proposal, hmac_key)
    return _hmac.compare_digest(expected, signature)


def is_quorum_reached(signatures: Mapping[str, str], members: Iterable[str]) -> bool:
    """≥2/3 of members signed (counted by distinct node_id)."""
    member_set = {m for m in members if m}
    if not member_set:
        return False
    signed = sum(1 for m in member_set if m in signatures)
    threshold = (2 * len(member_set) + 2) // 3  # ceil(2N/3)
    return signed >= threshold


@dataclass
class CheckpointVerificationReport:
    matches_merkle: bool
    local_merkle_root: str
    confirmed_merkle_root: str
    checkpoint_round: int
    has_tamper_evidence: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "matches_merkle": self.matches_merkle,
            "local_merkle_root": self.local_merkle_root,
            "confirmed_merkle_root": self.confirmed_merkle_root,
            "checkpoint_round": self.checkpoint_round,
            "has_tamper_evidence": self.has_tamper_evidence,
            "notes": list(self.notes),
        }
