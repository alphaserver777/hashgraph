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
