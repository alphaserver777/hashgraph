"""Tests for service lifecycle events (start / stop / killed)."""
from __future__ import annotations

import pytest

from mdrj.config import (
    GossipConfig,
    HeartbeatConfig,
    LinuxIngestConfig,
    NodeConfig,
    PrioritizationConfig,
    SecurityConfig,
    StorageConfig,
)
from mdrj.models import NodeProfile
from mdrj.node import Node


def _make_config(tmp_path, db_name: str = "node.db") -> NodeConfig:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    return NodeConfig(
        node_id="lifecycle-test",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=None),
        storage=StorageConfig(sqlite_path=str(tmp_path / db_name)),
        linux_ingest=LinuxIngestConfig(),
        heartbeat=HeartbeatConfig(enabled=False),
    )


def _own_lifecycle(node: Node) -> list[dict]:
    """Все service-lifecycle события, эмитированные этим узлом, по порядку."""
    events = node.storage.all_events()
    own = [
        e for e in events
        if e.creator == node.config.node_id
        and (e.payload or {}).get("event_kind") in Node.SERVICE_LIFECYCLE_KINDS
    ]
    own.sort(key=lambda e: e.ts_local)
    return [(e.payload or {}) for e in own]


@pytest.mark.asyncio
async def test_first_start_emits_only_service_start(tmp_path):
    """Самый первый запуск: история пуста, никакого killed."""
    node = Node(_make_config(tmp_path))
    await node.start()
    try:
        lifecycle = _own_lifecycle(node)
        kinds = [p["event_kind"] for p in lifecycle]
        assert kinds == ["mdrj_service_start"]
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_clean_stop_emits_stop_event(tmp_path):
    node = Node(_make_config(tmp_path))
    await node.start()
    await node.stop()

    # Перезапускаем (новый Node на том же storage) чтобы прочитать историю
    node2 = Node(_make_config(tmp_path))
    lifecycle = _own_lifecycle(node2)
    kinds = [p["event_kind"] for p in lifecycle]
    assert kinds == ["mdrj_service_start", "mdrj_service_stop"]


@pytest.mark.asyncio
async def test_clean_cycle_no_killed_detected(tmp_path):
    """Полный цикл start→stop→start: killed НЕ эмитится."""
    node = Node(_make_config(tmp_path))
    await node.start()
    await node.stop()
    node2 = Node(_make_config(tmp_path))
    await node2.start()
    try:
        lifecycle = _own_lifecycle(node2)
        kinds = [p["event_kind"] for p in lifecycle]
        assert "mdrj_service_killed" not in kinds
        # Должна быть последовательность start→stop→start
        assert kinds[0] == "mdrj_service_start"
        assert "mdrj_service_stop" in kinds
        assert kinds[-1] == "mdrj_service_start"
    finally:
        await node2.stop()


@pytest.mark.asyncio
async def test_kill_without_stop_detected_on_next_start(tmp_path):
    """Имитируем kill -9: start есть, stop НЕ эмитим, перезапускаем — должно быть killed."""
    node = Node(_make_config(tmp_path))
    await node.start()
    # Имитация "kill -9": не вызываем stop, просто закрываем storage
    node.storage.close()

    # Перезапуск: должен обнаружить незакрытый предыдущий start
    node2 = Node(_make_config(tmp_path))
    await node2.start()
    try:
        lifecycle = _own_lifecycle(node2)
        kinds = [p["event_kind"] for p in lifecycle]
        # ожидаем: предыдущий start, потом killed, потом новый start
        assert kinds == ["mdrj_service_start", "mdrj_service_killed", "mdrj_service_start"]
        # killed должен ссылаться на тот предыдущий start
        killed_payload = next(p for p in lifecycle if p["event_kind"] == "mdrj_service_killed")
        assert killed_payload.get("previous_start_id")
        assert killed_payload.get("previous_start_ts") is not None
    finally:
        await node2.stop()


@pytest.mark.asyncio
async def test_killed_event_is_class_A(tmp_path):
    """killed это критичное событие → класс А."""
    node = Node(_make_config(tmp_path))
    await node.start()
    node.storage.close()

    node2 = Node(_make_config(tmp_path))
    await node2.start()
    try:
        events = node2.storage.all_events()
        killed = [
            e for e in events
            if (e.payload or {}).get("event_kind") == "mdrj_service_killed"
        ]
        assert len(killed) == 1
        assert killed[0].cls.value == "A"
    finally:
        await node2.stop()
