"""Тесты часового диагностического снимка (замена heartbeat)."""
from __future__ import annotations

import asyncio

import pytest

from mdrj.config import (
    GossipConfig,
    HeartbeatConfig,
    LinuxIngestConfig,
    NodeConfig,
    PrioritizationConfig,
    RuntimeConfig,
    SecurityConfig,
    StorageConfig,
)
from mdrj.models import EventClass, NodeProfile
from mdrj.node import Node


def _config(tmp_path, *, hourly_interval: float = 0.0) -> NodeConfig:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    return NodeConfig(
        node_id="hourly-test",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=None),
        storage=StorageConfig(sqlite_path=str(tmp_path / "node.db")),
        linux_ingest=LinuxIngestConfig(),
        heartbeat=HeartbeatConfig(enabled=False),
        runtime=RuntimeConfig(hourly_status_interval_sec=hourly_interval),
    )


def test_disabled_by_default():
    cfg = RuntimeConfig()
    assert cfg.hourly_status_interval_sec == 0.0


@pytest.mark.asyncio
async def test_hourly_status_task_not_started_when_zero(tmp_path):
    node = Node(_config(tmp_path, hourly_interval=0.0))
    await node.start()
    try:
        assert node._hourly_status_task is None
        status = node.hourly_status_runtime()
        assert status["enabled"] is False
        assert status["running"] is False
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_hourly_status_emits_on_short_interval(tmp_path):
    node = Node(_config(tmp_path, hourly_interval=70.0))  # >60c минимум в loop
    await node.start()
    try:
        status = node.hourly_status_runtime()
        assert status["enabled"] is True
        assert status["running"] is True
        # Прямой вызов одного emit, без ожидания окна.
        await node._emit_hourly_status()
        # Проверяем что событие сохранено.
        events = [
            e for e in node.storage.all_events()
            if (e.payload or {}).get("event_kind") == "node_hourly_status"
        ]
        assert len(events) == 1
        e = events[0]
        assert e.cls == EventClass.B
        payload = e.payload or {}
        for key in (
            "node_id", "host_id",
            "process_uptime_sec", "host_uptime_sec",
            "collectors", "events_in_window",
            "load_avg_1m", "mem_used_pct", "disk_used_pct_root",
            "last_confirmed_checkpoint_round", "last_checkpoint_age_sec",
            "peers_known",
        ):
            assert key in payload, f"missing key {key}"
        # collectors — list; events_in_window — dict с A/B/C ключами.
        assert isinstance(payload["collectors"], list)
        ew = payload["events_in_window"]
        assert set(ew.keys()) >= {"A", "B", "C"}
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_hourly_status_window_resets_after_emit(tmp_path):
    node = Node(_config(tmp_path, hourly_interval=70.0))
    await node.start()
    try:
        await node._emit_hourly_status()
        cnt1 = node._hourly_status_emitted
        # Эмитим класс A — должно появиться в events_by_class.
        await node.emit_event(EventClass.A, {"event_kind": "admin_ssh_login_success",
                                              "host_id": "h", "node_id": "n"})
        await node._emit_hourly_status()
        # Второй снимок должен показать 1 событие A в окне.
        events = [
            e for e in node.storage.all_events()
            if (e.payload or {}).get("event_kind") == "node_hourly_status"
        ]
        events.sort(key=lambda x: x.ts_local)
        last = events[-1]
        # На втором снимке events_in_window["A"] >= 1
        # (учтём что сам hourly_status — класс B и тоже учитывается между окнами).
        assert (last.payload or {})["events_in_window"]["A"] >= 1
        assert node._hourly_status_emitted == cnt1 + 1
    finally:
        await node.stop()


def test_event_kind_registered():
    """node_hourly_status зарегистрирован в каталоге как класс B."""
    from mdrj.event_catalog import event_class_for, is_known_event_kind
    assert is_known_event_kind("node_hourly_status")
    assert event_class_for("node_hourly_status") == EventClass.B


@pytest.mark.asyncio
async def test_liveness_includes_hourly_status_in_prometheus(tmp_path):
    """prometheus_extras должен видеть node_hourly_status как liveness-сигнал."""
    from mdrj.prometheus_extras import build_extras

    node = Node(_config(tmp_path, hourly_interval=70.0))
    await node.start()
    try:
        await node._emit_hourly_status()
        series = build_extras(node)
        hb_series = next((s for s in series if s.name == "mdrj_heartbeat_last_seconds_ago"), None)
        assert hb_series is not None
        # Должна быть запись для собственного узла.
        own = [s for s in hb_series.samples if s.labels.get("peer") == node.config.node_id]
        assert own, "узел не виден в liveness-серии после node_hourly_status"
        assert own[0].value < 5.0
    finally:
        await node.stop()
