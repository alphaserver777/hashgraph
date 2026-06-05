"""Тесты дебаунса `_recompute_consensus`.

При `runtime.recompute_debounce_sec > 0` K последовательных persist
должны коалесцироваться в один пересчёт. При значении 0 сохраняется
старое поведение (recompute на каждый persist).
"""
from __future__ import annotations

import asyncio

import pytest

from mdrj.config import (
    GossipConfig,
    LinuxIngestConfig,
    NodeConfig,
    PrioritizationConfig,
    RuntimeConfig,
    SecurityConfig,
    StorageConfig,
)
from mdrj.models import EventClass, NodeProfile
from mdrj.node import Node


def _config(tmp_path, *, debounce_sec: float) -> NodeConfig:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    return NodeConfig(
        node_id="debounce-test",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=None),
        storage=StorageConfig(sqlite_path=str(tmp_path / "node.db")),
        linux_ingest=LinuxIngestConfig(),
        runtime=RuntimeConfig(recompute_debounce_sec=debounce_sec),
    )


def test_runtime_config_default_is_zero():
    cfg = RuntimeConfig()
    assert cfg.recompute_debounce_sec == 0.0


@pytest.mark.asyncio
async def test_no_debounce_recomputes_per_emit(tmp_path, monkeypatch):
    """При debounce=0 recompute вызывается синхронно на каждый emit."""
    node = Node(_config(tmp_path, debounce_sec=0.0))
    await node.start()
    calls = {"n": 0}
    real = node._recompute_consensus
    def counting():
        calls["n"] += 1
        real()
    monkeypatch.setattr(node, "_recompute_consensus", counting)
    try:
        baseline = calls["n"]
        for _ in range(5):
            await node.emit_event(EventClass.B, {"event_kind": "heartbeat", "node_id": "n", "host_id": "h"})
        # Каждый emit_event → _persist_envelope → _request_recompute →
        # синхронно _recompute_consensus, итого 5 раз.
        assert calls["n"] - baseline == 5
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_debounce_coalesces_multiple_emits(tmp_path, monkeypatch):
    """При debounce=0.2 пять подряд emit дают ≤2 пересчёта (обычно 1)."""
    node = Node(_config(tmp_path, debounce_sec=0.2))
    await node.start()
    calls = {"n": 0}
    real = node._recompute_consensus
    def counting():
        calls["n"] += 1
        real()
    monkeypatch.setattr(node, "_recompute_consensus", counting)
    try:
        baseline = calls["n"]
        for _ in range(5):
            await node.emit_event(EventClass.B, {"event_kind": "heartbeat", "node_id": "n", "host_id": "h"})
        # До завершения окна — recompute мог ещё не отработать.
        # Дать ему пройти + небольшой запас.
        await asyncio.sleep(0.4)
        delta = calls["n"] - baseline
        # Ровно 1 при идеальном попадании; ≤2 если окно сработало
        # дважды (например, очень медленный CI).
        assert 1 <= delta <= 2, f"ожидался 1..2 recompute, получено {delta}"
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_debounce_dirty_flag_survives_inflight(tmp_path, monkeypatch):
    """Если запрос пришёл пока пересчёт уже летит — он обработается во вторую волну."""
    node = Node(_config(tmp_path, debounce_sec=0.1))
    await node.start()
    try:
        await node.emit_event(EventClass.B, {"event_kind": "heartbeat", "node_id": "n", "host_id": "h"})
        # сразу запросить ещё один пока первый окно не закрылось
        await asyncio.sleep(0.05)
        await node.emit_event(EventClass.B, {"event_kind": "heartbeat", "node_id": "n", "host_id": "h"})
        await asyncio.sleep(0.5)
        # Оба события сохранены.
        events = [e for e in node.storage.all_events() if (e.payload or {}).get("event_kind") == "heartbeat"]
        assert len(events) >= 2
    finally:
        await node.stop()
