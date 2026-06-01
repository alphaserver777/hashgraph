"""Tests for HostLifecycleCollector."""
from __future__ import annotations

import time

import pytest

from mdrj.collectors.host_lifecycle import (
    HostLifecycleCollector,
    HostLifecycleCollectorConfig,
)


def _write_uptime(path, seconds: float, idle: float = 0.0) -> None:
    path.write_text(f"{seconds} {idle}\n", encoding="ascii")


def test_first_poll_emits_host_boot(tmp_path):
    uptime_path = tmp_path / "uptime"
    _write_uptime(uptime_path, 12345.6)
    cfg = HostLifecycleCollectorConfig(enabled=True, proc_uptime_path=str(uptime_path))
    coll = HostLifecycleCollector(config=cfg, node_id="node-1")
    events = coll.poll()
    kinds = [e.event_kind for e in events]
    assert kinds == ["host_boot"]
    payload = events[0].payload
    assert payload["category"] == "system_lifecycle"
    assert payload["uptime_at_observation_sec"] == pytest.approx(12345.6, rel=0.01)
    assert "boot_time" in payload


def test_second_poll_without_reboot_is_silent(tmp_path):
    uptime_path = tmp_path / "uptime"
    _write_uptime(uptime_path, 12345.6)
    cfg = HostLifecycleCollectorConfig(enabled=True, proc_uptime_path=str(uptime_path))
    coll = HostLifecycleCollector(config=cfg, node_id="node-1")
    coll.poll()  # boot
    # время идёт, uptime растёт соответственно (но boot_time остаётся примерно тем же)
    _write_uptime(uptime_path, 12350.0)
    events = coll.poll()
    assert events == []


def test_reboot_detected_on_uptime_reset(tmp_path):
    uptime_path = tmp_path / "uptime"
    _write_uptime(uptime_path, 200000.0)  # боловек давно загружен
    cfg = HostLifecycleCollectorConfig(
        enabled=True,
        proc_uptime_path=str(uptime_path),
        boot_time_drift_threshold_sec=10.0,
    )
    coll = HostLifecycleCollector(config=cfg, node_id="node-1")
    coll.poll()  # host_boot
    # имитируем перезагрузку: uptime обнулился, boot_time сильно сдвинулся
    _write_uptime(uptime_path, 5.0)
    events = coll.poll()
    assert [e.event_kind for e in events] == ["host_reboot"]
    payload = events[0].payload
    assert payload["previous_boot_time"] < payload["new_boot_time"]
    assert payload["drift_sec"] > 10.0


def test_disabled_collector_returns_nothing(tmp_path):
    uptime_path = tmp_path / "uptime"
    _write_uptime(uptime_path, 100.0)
    cfg = HostLifecycleCollectorConfig(enabled=False, proc_uptime_path=str(uptime_path))
    coll = HostLifecycleCollector(config=cfg, node_id="node-1")
    assert coll.poll() == []


def test_missing_uptime_file_does_not_crash(tmp_path):
    missing = tmp_path / "nonexistent"
    cfg = HostLifecycleCollectorConfig(enabled=True, proc_uptime_path=str(missing))
    coll = HostLifecycleCollector(config=cfg, node_id="node-1")
    # инициализация должна сама отключить коллектор; poll вернёт пусто
    assert coll.poll() == []
    assert coll.status.enabled is False


def test_annotation_adds_host_id(tmp_path):
    uptime_path = tmp_path / "uptime"
    _write_uptime(uptime_path, 42.0)
    cfg = HostLifecycleCollectorConfig(enabled=True, proc_uptime_path=str(uptime_path))
    coll = HostLifecycleCollector(config=cfg, node_id="node-1", host_id="host-A")
    events = coll.poll()
    assert events[0].payload.get("host_id") == "host-A"
    assert events[0].payload.get("node_id") == "node-1"
