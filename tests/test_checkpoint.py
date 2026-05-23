"""Tests for checkpoint mechanism (Этап 3.a)."""
from __future__ import annotations

from dataclasses import replace
from typing import List

import pytest

from mdrj.checkpoint import (
    CheckpointProposal,
    compute_merkle_root,
    is_quorum_reached,
    sign_proposal,
    verify_proposal_signature,
)
from mdrj.config import (
    GossipConfig,
    LinuxIngestConfig,
    NodeConfig,
    PrioritizationConfig,
    SecurityConfig,
    StorageConfig,
)
from mdrj.models import Event, EventClass, NodeProfile
from mdrj.node import Node


def _make_event(*, source: str, payload: dict, round_received: int) -> Event:
    ev = Event.create(
        cls_name=EventClass.A,
        source=source,
        ts_local=1.0,
        vclock={source: 1},
        parents=[],
        payload=payload,
    )
    ev.round_received = round_received
    ev.consensus_ts = 1.0 + round_received
    return ev


def test_merkle_root_is_deterministic_under_reorder():
    events = [
        _make_event(source="node-1", payload={"v": 1}, round_received=2),
        _make_event(source="node-2", payload={"v": 2}, round_received=1),
        _make_event(source="node-3", payload={"v": 3}, round_received=3),
    ]
    root_a = compute_merkle_root(events)
    root_b = compute_merkle_root(list(reversed(events)))
    assert root_a == root_b
    assert len(root_a) == 64


def test_merkle_root_changes_when_payload_changes():
    base = _make_event(source="x", payload={"a": 1}, round_received=1)
    mutated = _make_event(source="x", payload={"a": 2}, round_received=1)
    assert compute_merkle_root([base]) != compute_merkle_root([mutated])


def test_proposal_signature_roundtrip():
    proposal = CheckpointProposal(
        round_received=42,
        merkle_root="a" * 64,
        members_snapshot_hash="b" * 64,
        proposer_node_id="node-1",
    )
    sig = sign_proposal(proposal, "shared-secret")
    assert verify_proposal_signature(proposal, sig, "shared-secret")
    assert not verify_proposal_signature(proposal, sig, "other-secret")


def test_quorum_reaches_at_two_thirds():
    members = ["a", "b", "c"]
    assert is_quorum_reached({"a": "sig"}, members) is False
    assert is_quorum_reached({"a": "sig", "b": "sig"}, members) is True
    assert is_quorum_reached({"a": "sig", "b": "sig", "c": "sig"}, members) is True


def test_quorum_ignores_non_members():
    assert is_quorum_reached({"a": "x", "stranger": "x"}, ["a", "b", "c"]) is False


def _make_node(tmp_path, *, node_id: str = "node-1", hmac_key: str = "k") -> Node:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    cfg = NodeConfig(
        node_id=node_id,
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=hmac_key),
        storage=StorageConfig(sqlite_path=str(tmp_path / f"{node_id}.db")),
        linux_ingest=LinuxIngestConfig(),
    )
    return Node(cfg)


def _seed_events(node: Node, count: int) -> None:
    """Insert deterministic events with round_received assigned."""
    for i in range(count):
        event = Event.create(
            cls_name=EventClass.A,
            source=node.config.node_id,
            ts_local=float(i),
            vclock={node.config.node_id: i + 1},
            parents=[],
            payload={"i": i},
        )
        event.round_received = i
        event.consensus_ts = float(i)
        # Persist via storage low-level path (bypass _persist_envelope WIP-recompute)
        from mdrj.models import Envelope

        envelope = Envelope(event=event, path_meta=[])
        node.storage.store_envelope(envelope, event.consensus_ts)


def test_node_propose_local_checkpoint_records_self_signature(tmp_path):
    node = _make_node(tmp_path)
    _seed_events(node, 5)
    proposal = node.propose_local_checkpoint(target_round=4)
    assert proposal["merkle_root"]
    assert proposal["proposer_node_id"] == "node-1"
    saved = node.storage.get_checkpoint(4)
    assert saved is not None
    assert "node-1" in saved["signatures"]


def test_node_quorum_confirms_checkpoint_with_three_signers(tmp_path):
    # Single node "votes" three times by pretending to be three different node_ids.
    node = _make_node(tmp_path)
    _seed_events(node, 3)
    # Register three peers so membership snapshot has size 3.
    for nid, addr in (("node-1", "self:node-1"), ("node-2", "10.0.0.2:9001"), ("node-3", "10.0.0.3:9001")):
        node.storage.ensure_peer(
            addr, node_id=nid, last_seen=1.0, healthy=True, enabled=True, role="node"
        )
    # membership snapshot is rebuilt lazily from peer-registry on first access
    # Generate proposals from three "proposers"
    from mdrj.checkpoint import CheckpointProposal, sign_proposal

    members_hash = node._membership_snapshot_hash()
    merkle = node.propose_local_checkpoint(target_round=2)["merkle_root"]
    for nid in ("node-2", "node-3"):
        proposal = CheckpointProposal(
            round_received=2,
            merkle_root=merkle,
            members_snapshot_hash=members_hash,
            proposer_node_id=nid,
        )
        proposal.signature = sign_proposal(proposal, "k")
        node.ingest_checkpoint_proposal(proposal.to_dict())
    saved = node.storage.get_checkpoint(2)
    assert saved["status"] == "confirmed"
    assert set(saved["signatures"].keys()) == {"node-1", "node-2", "node-3"}


def test_verify_checkpoint_detects_tampering(tmp_path):
    node = _make_node(tmp_path)
    _seed_events(node, 3)
    node.propose_local_checkpoint(target_round=2)
    # Add fake peers and re-record signatures so it confirms.
    from mdrj.checkpoint import CheckpointProposal, sign_proposal

    for nid in ("node-2", "node-3"):
        node.storage.ensure_peer(f"10.0.0.{nid[-1]}:9001", node_id=nid, last_seen=1.0, healthy=True, enabled=True, role="node")
    # membership snapshot is rebuilt lazily from peer-registry on first access
    merkle = node.storage.get_checkpoint(2)["merkle_root"]
    members_hash = node._membership_snapshot_hash()
    for nid in ("node-2", "node-3"):
        proposal = CheckpointProposal(
            round_received=2,
            merkle_root=merkle,
            members_snapshot_hash=members_hash,
            proposer_node_id=nid,
        )
        proposal.signature = sign_proposal(proposal, "k")
        node.ingest_checkpoint_proposal(proposal.to_dict())
    assert node.storage.get_checkpoint(2)["status"] == "confirmed"

    # Tamper with one stored event's payload directly in SQLite.
    node.storage._conn.execute(
        "UPDATE events SET payload = ? WHERE round_received = 0", ('{"i": 999}',)
    )
    node.storage._conn.commit()

    report = node.verify_checkpoint(2)
    assert report["matches_merkle"] is False
    assert report["has_tamper_evidence"] is True


def test_ingest_rejects_invalid_signature(tmp_path):
    node = _make_node(tmp_path, hmac_key="k")
    _seed_events(node, 1)
    from mdrj.checkpoint import CheckpointProposal

    bad = CheckpointProposal(
        round_received=0,
        merkle_root="a" * 64,
        members_snapshot_hash="",
        proposer_node_id="node-2",
        signature="0" * 64,
    )
    with pytest.raises(ValueError):
        node.ingest_checkpoint_proposal(bad.to_dict())
