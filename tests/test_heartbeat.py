"""Tests for the liveness heartbeat loop."""
from __future__ import annotations

import asyncio

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


def _make_config(tmp_path, *, heartbeat: HeartbeatConfig) -> NodeConfig:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    return NodeConfig(
        node_id="hb-test",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=None),
        storage=StorageConfig(sqlite_path=str(tmp_path / "node.db")),
        linux_ingest=LinuxIngestConfig(),
        heartbeat=heartbeat,
    )


def test_heartbeat_disabled_by_default(tmp_path):
    node = Node(_make_config(tmp_path, heartbeat=HeartbeatConfig()))
    status = node.heartbeat_status()
    assert status["enabled"] is False
    assert status["emitted_count"] == 0
    assert status["running"] is False


@pytest.mark.asyncio
async def test_heartbeat_emits_when_enabled(tmp_path):
    # 0.1s interval так чтобы тест шёл быстро
    cfg = _make_config(tmp_path, heartbeat=HeartbeatConfig(enabled=True, interval_sec=0.1))
    node = Node(cfg)
    await node.start()
    try:
        # Дать минимум 3 итерациям отработать
        await asyncio.sleep(0.7)
        status = node.heartbeat_status()
        assert status["running"] is True
        assert status["emitted_count"] >= 3, f"expected ≥3 heartbeats, got {status['emitted_count']}"
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_heartbeat_writes_class_c_event_kind(tmp_path):
    cfg = _make_config(tmp_path, heartbeat=HeartbeatConfig(enabled=True, interval_sec=0.1))
    node = Node(cfg)
    await node.start()
    try:
        await asyncio.sleep(0.3)
        events = node.storage.all_events()
        heartbeats = [
            e for e in events
            if (e.payload or {}).get("event_kind") == "heartbeat"
        ]
        assert len(heartbeats) >= 1
        sample = heartbeats[-1]
        assert sample.cls.value == "C"
        p = sample.payload or {}
        assert p.get("purpose") == "liveness"
        assert p.get("node_id") == "hb-test"
        assert p.get("interval_sec") == 0.1
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_heartbeat_stops_cleanly(tmp_path):
    cfg = _make_config(tmp_path, heartbeat=HeartbeatConfig(enabled=True, interval_sec=0.1))
    node = Node(cfg)
    await node.start()
    await asyncio.sleep(0.25)
    assert node.heartbeat_status()["running"] is True
    await node.stop()
    # После stop задача очищена
    assert node.heartbeat_status()["running"] is False
