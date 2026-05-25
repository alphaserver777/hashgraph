"""Tests for retention with checkpoint-anchored GC (Этап 3.b)."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Dict, List

import pytest

from mdrj.checkpoint import CheckpointProposal, sign_proposal
from mdrj.config import (
    GossipConfig,
    LinuxIngestConfig,
    NodeConfig,
    PrioritizationConfig,
    RetentionConfig,
    SecurityConfig,
    StorageConfig,
)
from mdrj.models import Envelope, Event, EventClass, NodeProfile
from mdrj.node import Node


def _make_node(tmp_path: Path, *, hmac_key: str = "k", retention: RetentionConfig = None) -> Node:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    cfg = NodeConfig(
        node_id="node-1",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=hmac_key),
        storage=StorageConfig(sqlite_path=str(tmp_path / "n.db")),
        linux_ingest=LinuxIngestConfig(),
        retention=retention or RetentionConfig(),
    )
    return Node(cfg)


def _seed_events(node: Node, count: int, *, cls: EventClass = EventClass.B, age_seconds: float = 0.0) -> List[str]:
    """Seed events directly via storage. Optionally backdate them via created_at."""
    ids: List[str] = []
    base_ts = time.time() - age_seconds
    for i in range(count):
        event = Event.create(
            cls_name=cls,
            source=node.config.node_id,
            ts_local=base_ts + i,
            vclock={node.config.node_id: i + 1},
            parents=[],
            payload={"i": i, "cls": cls.value},
        )
        event.round_received = i
        event.consensus_ts = float(i)
        envelope = Envelope(event=event, path_meta=[])
        node.storage.store_envelope(envelope, event.consensus_ts)
        # Backdate created_at if needed to bypass max_age threshold in tests.
        if age_seconds > 0:
            node.storage._conn.execute(
                "UPDATE events SET created_at = ? WHERE id = ?",
                (base_ts + i, event.id),
            )
            node.storage._conn.commit()
        ids.append(event.id)
    return ids


def _confirm_checkpoint(node: Node, target_round: int) -> Dict[str, object]:
    """Force-confirm a checkpoint at target_round by adding 3 fake signatures."""
    for nid in ("node-1", "node-2", "node-3"):
        node.storage.ensure_peer(
            f"self:{nid}" if nid == "node-1" else f"10.0.0.{nid[-1]}:9001",
            node_id=nid,
            last_seen=1.0,
            healthy=True,
            enabled=True,
            role="node",
        )
    proposal_dict = node.propose_local_checkpoint(target_round=target_round)
    merkle = proposal_dict["merkle_root"]
    members_hash = node._membership_snapshot_hash()
    for nid in ("node-2", "node-3"):
        proposal = CheckpointProposal(
            round_received=target_round,
            merkle_root=merkle,
            members_snapshot_hash=members_hash,
            proposer_node_id=nid,
        )
        proposal.signature = sign_proposal(proposal, "k")
        node.ingest_checkpoint_proposal(proposal.to_dict())
    return node.storage.get_checkpoint(target_round)


def test_retention_disabled_does_nothing(tmp_path):
    node = _make_node(tmp_path, retention=RetentionConfig(enabled=False))
    _seed_events(node, 5)
    result = node.run_retention_once()
    assert result["status"] == "disabled"
    assert node.storage.event_count() == 5


def test_retention_no_op_without_confirmed_checkpoint(tmp_path):
    node = _make_node(tmp_path, retention=RetentionConfig(enabled=True, max_age_days=0))
    _seed_events(node, 5)
    result = node.run_retention_once()
    assert result["status"] == "no_confirmed_checkpoint"
    assert node.storage.event_count() == 5


def test_retention_prunes_b_class_under_confirmed_checkpoint(tmp_path):
    node = _make_node(
        tmp_path,
        retention=RetentionConfig(enabled=True, max_age_days=0, keep_class_a=True),
    )
    _seed_events(node, 5, cls=EventClass.B, age_seconds=10.0)
    _confirm_checkpoint(node, target_round=4)
    result = node.run_retention_once()
    assert result["status"] == "ok"
    assert result["pruned"] == 5
    assert node.storage.event_count() == 0
    skeletons = node.storage.list_event_skeletons(limit=10)
    assert len(skeletons) == 5
    assert all("payload_hash" in s for s in skeletons)


def test_retention_keeps_class_a_when_enabled(tmp_path):
    node = _make_node(
        tmp_path,
        retention=RetentionConfig(enabled=True, max_age_days=0, keep_class_a=True),
    )
    _seed_events(node, 3, cls=EventClass.A, age_seconds=10.0)
    _seed_events(node, 3, cls=EventClass.B, age_seconds=10.0)
    # round_received 0..2 for A, 0..2 also for B (separate seeding). For test
    # determinism, confirm checkpoint at largest round.
    _confirm_checkpoint(node, target_round=2)
    result = node.run_retention_once()
    assert result["pruned"] == 3  # only Bs pruned, As kept
    classes = {e.cls.value for e in node.storage.all_events()}
    assert "A" in classes
    assert "B" not in classes


def test_retention_respects_max_age(tmp_path):
    node = _make_node(
        tmp_path,
        retention=RetentionConfig(enabled=True, max_age_days=1, keep_class_a=False),
    )
    # All events are fresh (created_at = now), so prune should skip them all.
    _seed_events(node, 5, cls=EventClass.B, age_seconds=0.0)
    _confirm_checkpoint(node, target_round=4)
    result = node.run_retention_once()
    assert result["pruned"] == 0  # too young
    assert node.storage.event_count() == 5


def test_retention_writes_cold_archive(tmp_path):
    archive_path = tmp_path / "archive.jsonl"
    node = _make_node(
        tmp_path,
        retention=RetentionConfig(
            enabled=True,
            max_age_days=0,
            keep_class_a=False,
            archive_path=str(archive_path),
        ),
    )
    _seed_events(node, 3, cls=EventClass.B, age_seconds=10.0)
    _confirm_checkpoint(node, target_round=2)
    node.run_retention_once()
    assert archive_path.exists()
    lines = [line for line in archive_path.read_text().splitlines() if line.strip()]
    headers = [json.loads(line) for line in lines if '"_archive_header"' in line]
    records = [json.loads(line) for line in lines if '"_archive_header"' not in line]
    assert len(headers) == 1
    assert headers[0]["_archive_header"]["checkpoint_round"] == 2
    assert len(records) == 3
    # Every record stores its own payload_hash matching its payload.
    for record in records:
        actual = hashlib.sha256(
            json.dumps(record["payload"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert actual == record["payload_hash"]


def test_event_skeleton_preserves_parent_ids(tmp_path):
    node = _make_node(
        tmp_path,
        retention=RetentionConfig(enabled=True, max_age_days=0, keep_class_a=False),
    )
    # Build 3 events with parent linkage: 0 → 1 → 2
    parents: List[str] = []
    for i in range(3):
        event = Event.create(
            cls_name=EventClass.B,
            source="node-1",
            ts_local=float(i),
            vclock={"node-1": i + 1},
            parents=parents,
            payload={"i": i},
        )
        event.round_received = i
        event.consensus_ts = float(i)
        envelope = Envelope(event=event, path_meta=[])
        node.storage.store_envelope(envelope, event.consensus_ts)
        node.storage._conn.execute(
            "UPDATE events SET created_at = 0 WHERE id = ?", (event.id,)
        )
        node.storage._conn.commit()
        parents = [event.id]
    _confirm_checkpoint(node, target_round=2)
    node.run_retention_once()
    skeletons = node.storage.list_event_skeletons(limit=10)
    assert len(skeletons) == 3
    # The last skeleton should reference the second one's id as its parent.
    sorted_by_round = sorted(skeletons, key=lambda s: s["round_received"])
    assert sorted_by_round[1]["parent_ids"]  # child references a parent
    assert sorted_by_round[2]["parent_ids"]  # chain continues
