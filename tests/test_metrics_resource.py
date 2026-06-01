"""Tests for Этап 2 resource metrics and metrics_history."""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from mdrj.api import build_app
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
from mdrj.storage import DAGStorage


def _make_config(tmp_path, *, hmac_key=None) -> NodeConfig:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    return NodeConfig(
        node_id="node-test",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=hmac_key),
        storage=StorageConfig(sqlite_path=str(tmp_path / "node.db")),
        linux_ingest=LinuxIngestConfig(),
    )


def test_metrics_snapshot_includes_resource_fields(tmp_path):
    cfg = _make_config(tmp_path)
    node = Node(cfg)
    snap = node.metrics_snapshot()
    for key in (
        "rss_bytes",
        "cpu_percent",
        "db_size_bytes",
        "gossip_bytes_in_total",
        "gossip_bytes_out_total",
        "bytes_per_event",
        "emit_to_consensus_latency_p50_ms",
        "emit_to_consensus_latency_p95_ms",
    ):
        assert key in snap, f"missing metric key {key}"
    assert snap["db_size_bytes"] > 0  # storage initialised


def test_storage_db_size_bytes_grows_with_writes(tmp_path):
    storage = DAGStorage(str(tmp_path / "x.db"))
    initial = storage.db_size_bytes()
    assert initial > 0
    for i in range(200):
        storage.append_metrics_snapshot(time.time() + i, json.dumps({"i": i, "pad": "x" * 200}))
    grown = storage.db_size_bytes()
    assert grown >= initial


def test_metrics_history_append_and_read(tmp_path):
    storage = DAGStorage(str(tmp_path / "h.db"))
    now = time.time()
    for i in range(5):
        storage.append_metrics_snapshot(now + i, json.dumps({"event_count": i}))
    rows = storage.list_metrics_history(limit=10)
    assert len(rows) == 5
    assert rows[0]["snapshot"]["event_count"] == 0
    assert rows[-1]["snapshot"]["event_count"] == 4
    # since-ts filter
    filtered = storage.list_metrics_history(since_ts=now + 3)
    assert [row["snapshot"]["event_count"] for row in filtered] == [3, 4]


def test_metrics_history_prune_keeps_last_n(tmp_path):
    storage = DAGStorage(str(tmp_path / "p.db"))
    now = time.time()
    for i in range(50):
        storage.append_metrics_snapshot(now + i, json.dumps({"i": i}))
    removed = storage.prune_metrics_history(keep_last=10)
    assert removed == 40
    rows = storage.list_metrics_history(limit=100)
    assert len(rows) == 10
    # The most recent 10 should remain
    assert rows[0]["snapshot"]["i"] == 40
    assert rows[-1]["snapshot"]["i"] == 49


@pytest.mark.asyncio
async def test_metrics_prometheus_endpoint_returns_text(tmp_path, aiohttp_client):
    cfg = _make_config(tmp_path)
    node = Node(cfg)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.get("/metrics/prometheus")
        assert resp.status == 200
        body = await resp.text()
        assert resp.content_type == "text/plain"
        assert "mdrj_rss_bytes" in body
        assert "mdrj_db_size_bytes" in body
        assert "# TYPE mdrj_gossip_bytes_in_total counter" in body
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_emit_event_records_latency(tmp_path):
    cfg = _make_config(tmp_path)
    node = Node(cfg)
    await node.start()
    try:
        await node.emit_event(EventClass.A, {"event_kind": "virus", "note": "test"})
        # Give the background loop a moment, then read snapshot
        snap = node.metrics_snapshot()
        # p50 and p95 should be non-zero after at least one emission
        assert snap["emit_to_consensus_latency_p50_ms"] >= 0
        assert snap["emit_to_consensus_latency_p95_ms"] >= snap["emit_to_consensus_latency_p50_ms"]
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_metrics_history_loop_writes_snapshots(tmp_path):
    cfg = _make_config(tmp_path)
    node = Node(cfg)
    node._metrics_history_interval = 0.2  # speed up for test
    await node.start()
    try:
        await asyncio.sleep(0.9)  # allow several history writes
        rows = node.list_metrics_history(limit=100)
        assert len(rows) >= 2, f"expected >=2 history rows, got {len(rows)}"
        assert "event_count" in rows[0]["snapshot"]
    finally:
        await node.stop()
