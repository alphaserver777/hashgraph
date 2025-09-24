import asyncio

import pytest

from mdrj.config import GossipConfig, NodeConfig, PrioritizationConfig, SecurityConfig, StorageConfig
from mdrj.models import EventClass, NodeProfile
from mdrj.node import Node


def make_config(node_id: str, listen: str, peers: list[str], storage_path: str) -> NodeConfig:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="light", threat_level="HIGH")
    return NodeConfig(
        node_id=node_id,
        listen=listen,
        peers=peers,
        profile=profile,
        gossip=GossipConfig(period_sec=0.4, fan_out=2),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key="demo"),
        storage=StorageConfig(sqlite_path=storage_path),
    )


@pytest.mark.asyncio
async def test_gossip_replication(tmp_path):
    base_port = 9400
    configs: list[NodeConfig] = []
    nodes: list[Node] = []
    addresses = [f"127.0.0.1:{base_port + i}" for i in range(3)]
    for idx, address in enumerate(addresses):
        peers = [addr for addr in addresses if addr != address]
        cfg = make_config(f"node-{idx+1}", address, peers, str(tmp_path / f"node{idx+1}.db"))
        configs.append(cfg)
        node = Node(cfg)
        nodes.append(node)

    for node in nodes:
        await node.start()

    try:
        emission = await nodes[0].emit_event(EventClass.A, {"msg": "hello"})
        event_id = emission.event.id
        await asyncio.sleep(2.5)
        for node in nodes:
            stored = node.storage.get_event(event_id)
            assert stored is not None
            assert stored.payload["msg"] == "hello"
    finally:
        for node in nodes:
            await node.stop()

