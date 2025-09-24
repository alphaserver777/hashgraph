import asyncio

import pytest

from mdrj.config import GossipConfig, NodeConfig, PrioritizationConfig, SecurityConfig, StorageConfig
from mdrj.models import EventClass, NodeProfile
from mdrj.node import Node


def build_cfg(node_id: str, listen: str, peers: list[str], storage_path: str, threat: str = "LOW") -> NodeConfig:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="light", threat_level=threat)
    return NodeConfig(
        node_id=node_id,
        listen=listen,
        peers=peers,
        profile=profile,
        gossip=GossipConfig(period_sec=0.5, fan_out=2),
        prioritization=PrioritizationConfig(level_threshold_B="ELEV", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key="merge"),
        storage=StorageConfig(sqlite_path=storage_path),
    )


@pytest.mark.asyncio
async def test_merge_after_partition(tmp_path):
    addresses = [f"127.0.0.1:{9500 + i}" for i in range(3)]
    cfg1 = build_cfg("node-1", addresses[0], [addresses[1]], str(tmp_path / "node1.db"), threat="HIGH")
    cfg2 = build_cfg("node-2", addresses[1], [addresses[0]], str(tmp_path / "node2.db"), threat="HIGH")
    cfg3 = build_cfg("node-3", addresses[2], [], str(tmp_path / "node3.db"))

    nodes = [Node(cfg1), Node(cfg2), Node(cfg3)]
    for node in nodes:
        await node.start()

    try:
        e1 = await nodes[0].emit_event(EventClass.A, {"origin": "g1"})
        e2 = await nodes[1].emit_event(EventClass.B, {"origin": "g1"})
        e3 = await nodes[2].emit_event(EventClass.A, {"origin": "g2"})
        await asyncio.sleep(2)

        assert nodes[2].storage.get_event(e1.event.id) is None

        # heal partition: register cross peers
        for idx in (0, 1):
            nodes[idx].register_peer(addresses[2])
        nodes[2].register_peer(addresses[0])
        nodes[2].register_peer(addresses[1])

        await asyncio.sleep(3)

        for node in nodes:
            assert node.storage.get_event(e1.event.id) is not None
            assert node.storage.get_event(e2.event.id) is not None
            assert node.storage.get_event(e3.event.id) is not None
            snapshot = node.metrics_snapshot()
            assert snapshot["K_r"] >= 0.9
    finally:
        for node in nodes:
            await node.stop()

