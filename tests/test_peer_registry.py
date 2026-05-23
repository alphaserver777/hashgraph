from mdrj.storage import DAGStorage


def test_peer_registry_persists_enabled_and_note(tmp_path):
    db_path = tmp_path / "peer-registry.db"
    storage = DAGStorage(str(db_path))

    storage.ensure_peer(
        "198.51.100.10:9001",
        node_id="node-remote",
        last_seen=1700000000.0,
        healthy=True,
        enabled=True,
        note="seed",
        source="config",
        role="responder",
    )
    updated = storage.update_peer(
        "198.51.100.10:9001",
        enabled=False,
        note="исключён после компрометации",
        role="node",
        node_id="node-remote",
    )

    peers = storage.list_peers()

    assert updated is not None
    assert len(peers) == 1
    assert peers[0].enabled is False
    assert peers[0].note == "исключён после компрометации"
    assert peers[0].source == "config"
    assert peers[0].role == "node"
    assert peers[0].node_id == "node-remote"

    storage.delete_peer("198.51.100.10:9001")
    assert storage.list_peers() == []
    storage.close()
