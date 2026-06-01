from mdrj.models import Envelope, Event, EventClass
from mdrj.storage import DAGStorage
from mdrj.utils import utc_timestamp
from mdrj.config import load_config
from mdrj.node import Node


def make_anchor(idx: int) -> Envelope:
    event = Event.create(
        cls_name=EventClass.C,
        source="genesis",
        ts_local=utc_timestamp(),
        vclock={},
        parents=[],
        payload={"anchor": idx},
    )
    return Envelope(event=event, path_meta=[{"node": "genesis", "ts": event.ts_local}])


def test_storage_append_and_query(tmp_path):
    db_path = tmp_path / "test.db"
    storage = DAGStorage(str(db_path))
    anchor1 = make_anchor(1)
    anchor2 = make_anchor(2)
    storage.store_envelope(anchor1, anchor1.event.ts_local)
    storage.store_envelope(anchor2, anchor2.event.ts_local)

    event = Event.create(
        cls_name=EventClass.A,
        source="node-1",
        ts_local=utc_timestamp(),
        vclock={"node-1": 1},
        parents=[anchor1.event.id, anchor2.event.id],
        payload={"value": 42},
    )
    envelope = Envelope(event=event, path_meta=[{"node": "node-1", "ts": event.ts_local}])
    stored = storage.store_envelope(envelope, event.ts_local)
    assert stored is True

    fetched = storage.get_event(event.id)
    assert fetched is not None
    assert fetched.payload == {"value": 42}

    frontier = storage.get_frontier()
    frontier_ids = {item[0] for item in frontier}
    assert event.id in frontier_ids

    topo = storage.toposort()
    assert anchor1.event.id in topo and anchor2.event.id in topo and event.id in topo

    recent = storage.subdag_since(event.ts_local - 1)
    assert any(ev.id == event.id for ev in recent)

    removed = storage.gc_by_quota(memory_mb=0)
    assert removed >= 0

    storage.close()


def test_toposort_ignores_dangling_parent_edges(tmp_path):
    db_path = tmp_path / "dangling-edge.db"
    storage = DAGStorage(str(db_path))
    anchor = make_anchor(1)
    storage.store_envelope(anchor, anchor.event.ts_local)

    with storage._conn:
        storage._conn.execute(
            "INSERT OR IGNORE INTO edges(parent_id, child_id) VALUES (?, ?)",
            ("missing-parent", anchor.event.id),
        )

    assert storage.toposort() == [anchor.event.id]
    storage.close()


def test_storage_persists_fame_vote_trace_fields(tmp_path):
    db_path = tmp_path / "consensus-trace.db"
    storage = DAGStorage(str(db_path))
    anchor = make_anchor(1)
    storage.store_envelope(anchor, anchor.event.ts_local)

    event = Event.create(
        cls_name=EventClass.A,
        source="node-1",
        creator="node-1",
        ts_local=utc_timestamp(),
        vclock={"node-1": 1},
        parents=[anchor.event.id],
        payload={"value": "trace"},
    )
    storage.store_envelope(Envelope(event=event, path_meta=[{"node": "node-1", "ts": event.ts_local}]), None)
    storage.replace_consensus_state(
        [
            {
                "event_id": event.id,
                "creator": "node-1",
                "self_parent_id": anchor.event.id,
                "other_parent_id": None,
                "round": 0,
                "round_received": None,
                "is_witness": True,
                "is_famous_witness": False,
                "fame_decided": False,
                "fame_decision_round": None,
                "fame_decision_kind": "pending",
                "fame_needs_coin": True,
                "fame_coin_used": False,
                "fame_coin_round": None,
                "fame_vote_round": 2,
                "fame_vote_yes": 1,
                "fame_vote_no": 1,
                "consensus_ts": None,
            }
        ]
    )

    fetched = storage.get_event(event.id)
    assert fetched is not None
    assert fetched.fame_decision_kind == "pending"
    assert fetched.fame_needs_coin is True
    assert fetched.fame_coin_used is False
    assert fetched.fame_coin_round is None
    assert fetched.fame_vote_round == 2
    assert fetched.fame_vote_yes == 1
    assert fetched.fame_vote_no == 1
    storage.close()


def test_bootstrap_genesis_contains_node_identity_for_known_nodes(tmp_path):
    config_path = tmp_path / "node.yaml"
    db_path = tmp_path / "node.db"
    config_path.write_text(
        "\n".join(
            [
                'node_id: "node-1"',
                'listen: "0.0.0.0:9001"',
                "peers:",
                '  - "node2.example.net:9002"',
                '  - "node3.example.net:9003"',
                'profile:',
                '  role: "light"',
                "  memory_mb: 128",
                "  bw_kbps: 256",
                "  cpu_quota: 0.7",
                '  threat_level: "LOW"',
                "gossip:",
                "  period_sec: 1.0",
                "  fan_out: 1",
                "prioritization:",
                '  level_threshold_B: "ELEV"',
                "  max_batch_bytes: 32768",
                "security: {}",
                "storage:",
                f'  sqlite_path: "{db_path}"',
            ]
        ),
        encoding="utf-8",
    )
    node = Node(load_config(config_path))
    node._bootstrap_genesis(force=True)

    events = node.storage.all_events()
    payloads = [event.payload for event in events if event.payload.get("genesis")]

    assert len(payloads) == 3
    assert any(
        payload.get("identity_scope") == "self"
        and payload.get("subject_node_id") == "node-1"
        and payload.get("listen") == "0.0.0.0:9001"
        for payload in payloads
    )
    assert any(
        payload.get("identity_scope") == "known_peer"
        and payload.get("configured_peer_address") == "node2.example.net:9002"
        for payload in payloads
    )
    assert any(
        payload.get("identity_scope") == "known_peer"
        and payload.get("configured_peer_address") == "node3.example.net:9003"
        for payload in payloads
    )
    node.storage.close()


def test_legacy_profile_role_normalizes_to_node_and_self_registry_controls_status(tmp_path):
    config_path = tmp_path / "node-role.yaml"
    db_path = tmp_path / "node-role.db"
    config_path.write_text(
        "\n".join(
            [
                'node_id: "node-1"',
                'listen: "0.0.0.0:9001"',
                "peers: []",
                "profile:",
                '  role: "light"',
                "  memory_mb: 128",
                "  bw_kbps: 256",
                "  cpu_quota: 0.7",
                '  threat_level: "LOW"',
                "gossip:",
                "  period_sec: 1.0",
                "  fan_out: 1",
                "prioritization:",
                '  level_threshold_B: "ELEV"',
                "  max_batch_bytes: 32768",
                "security: {}",
                "storage:",
                f'  sqlite_path: "{db_path}"',
            ]
        ),
        encoding="utf-8",
    )
    config = load_config(config_path)
    assert config.profile.role == "node"

    node = Node(config)
    peers = node.list_peer_registry()
    self_peers = [peer for peer in peers if peer.is_self]
    assert len(self_peers) == 1
    assert self_peers[0].role == "node"
    assert node.status()["profile"]["role"] == "node"

    updated = node.update_peer(self_peers[0].address, role="responder", note="операторский узел")
    assert updated is not None
    assert updated.role == "responder"
    assert node.status()["profile"]["role"] == "responder"
    assert node.list_peers() == []
    node.storage.close()


def test_consensus_membership_snapshot_is_persisted_and_reconfigured(tmp_path):
    config_path = tmp_path / "node-consensus.yaml"
    db_path = tmp_path / "node-consensus.db"
    config_path.write_text(
        "\n".join(
            [
                'node_id: "node-1"',
                'listen: "0.0.0.0:9001"',
                "peers: []",
                "profile:",
                '  role: "node"',
                "  memory_mb: 128",
                "  bw_kbps: 256",
                "  cpu_quota: 0.7",
                '  threat_level: "LOW"',
                "gossip:",
                "  period_sec: 1.0",
                "  fan_out: 1",
                "prioritization:",
                '  level_threshold_B: "ELEV"',
                "  max_batch_bytes: 32768",
                "security: {}",
                "storage:",
                f'  sqlite_path: "{db_path}"',
            ]
        ),
        encoding="utf-8",
    )
    node = Node(load_config(config_path))
    snapshot = node.active_consensus_membership()
    assert snapshot["epoch"] == 1
    assert snapshot["membership_size"] == 1

    node.register_peer("198.51.100.20:9001", node_id="node-2")
    same_snapshot = node.active_consensus_membership()
    assert same_snapshot["membership_size"] == 1

    import asyncio

    reconfigured = asyncio.run(node.reconfigure_consensus_membership())
    assert reconfigured["epoch"] == 2
    assert reconfigured["membership_size"] == 2
    persisted = node.storage.get_consensus_membership_snapshot()
    assert persisted is not None
    assert persisted["epoch"] == 2
    node.storage.close()


def test_status_exposes_consensus_mismatch_state(tmp_path):
    config_path = tmp_path / "node-consensus-status.yaml"
    db_path = tmp_path / "node-consensus-status.db"
    config_path.write_text(
        "\n".join(
            [
                'node_id: "node-1"',
                'listen: "0.0.0.0:9001"',
                "peers: []",
                "profile:",
                '  role: "node"',
                "  memory_mb: 128",
                "  bw_kbps: 256",
                "  cpu_quota: 0.7",
                '  threat_level: "LOW"',
                "gossip:",
                "  period_sec: 1.0",
                "  fan_out: 1",
                "prioritization:",
                '  level_threshold_B: "ELEV"',
                "  max_batch_bytes: 32768",
                "security: {}",
                "storage:",
                f'  sqlite_path: "{db_path}"',
            ]
        ),
        encoding="utf-8",
    )
    node = Node(load_config(config_path))
    node._consensus_mismatch["node-2"] = 1
    node._consensus_mismatch["node-3"] = 3

    status = node.status()
    assert status["consensus_health"] == "mismatch"
    assert status["consensus_pending_peers"] == ["node-2"]
    assert status["consensus_mismatch_peers"] == ["node-3"]
    node.storage.close()
