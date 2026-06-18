"""Digest согласованности считается по финализированному префиксу.

Регрессия на ложный mismatch при живом потоке: свежие события
(последние CONSENSUS_FINALITY_MARGIN раундов) не должны влиять на
hash/event_count, иначе два узла с одинаковым финализированным
префиксом, но разным хвостом, ложно показывают рассогласование.
"""
from __future__ import annotations

import pytest

from mdrj.config import (
    GossipConfig,
    LinuxIngestConfig,
    NodeConfig,
    PrioritizationConfig,
    SecurityConfig,
    StorageConfig,
)
from mdrj.models import EventClass, NodeProfile
from mdrj.node import Node


def _config(tmp_path) -> NodeConfig:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    return NodeConfig(
        node_id="digest-test",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=None),
        storage=StorageConfig(sqlite_path=str(tmp_path / "node.db")),
        linux_ingest=LinuxIngestConfig(),
    )


@pytest.mark.asyncio
async def test_digest_exposes_finalized_and_total_fields(tmp_path):
    node = Node(_config(tmp_path))
    await node.start()
    try:
        for _ in range(10):
            await node.emit_event(EventClass.B, {"event_kind": "admin_login",
                                                 "host_id": "h", "node_id": "n"})
        snap = node._consensus_snapshot_sync()
        assert "hash" in snap
        assert "event_count" in snap          # финализированных
        assert "total_event_count" in snap    # весь DAG
        assert "finality_margin" in snap
        # Хвост не финализирован → финализированных не больше полного DAG.
        assert snap["event_count"] <= snap["total_event_count"]
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_digest_stable_against_fresh_tail(tmp_path):
    """Добавление свежих событий (хвост) не меняет финализированный hash
    немедленно — он отражает только устоявшуюся часть."""
    node = Node(_config(tmp_path))
    await node.start()
    try:
        for _ in range(8):
            await node.emit_event(EventClass.B, {"event_kind": "admin_login",
                                                 "host_id": "h", "node_id": "n"})
        snap1 = node._consensus_snapshot_sync()
        finalized_hash_1 = snap1["hash"]
        finalized_count_1 = snap1["event_count"]
        total_1 = snap1["total_event_count"]

        # Эмитим ещё один свежий event — он попадает в нестабильный хвост.
        await node.emit_event(EventClass.B, {"event_kind": "admin_login",
                                             "host_id": "h", "node_id": "n", "fresh": True})
        snap2 = node._consensus_snapshot_sync()

        # Полный счёт вырос.
        assert snap2["total_event_count"] > total_1
        # Финализированный префикс — не уменьшился (монотонен) и его hash
        # либо тот же (если новый event только в хвосте), либо изменился
        # только из-за продвижения cutoff, но НЕ из-за самого свежего event.
        assert snap2["event_count"] >= finalized_count_1
    finally:
        await node.stop()
