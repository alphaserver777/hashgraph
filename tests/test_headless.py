"""Тесты headless-режима узла (ui.enabled=false).

Headless-узел участвует в кворуме/gossip/checkpoint, но не обслуживает
web-UI. Проверяем условную регистрацию роутов в build_app.
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
from mdrj.models import NodeProfile
from mdrj.node import Node


def _config(tmp_path, *, ui_enabled: bool) -> NodeConfig:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    return NodeConfig(
        node_id="headless-test",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=None),
        storage=StorageConfig(sqlite_path=str(tmp_path / "node.db")),
        linux_ingest=LinuxIngestConfig(),
        ui_enabled=ui_enabled,
    )


def test_ui_enabled_default_true():
    cfg = NodeConfig(
        node_id="x", listen="127.0.0.1:0", peers=[],
        profile=NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="LOW"),
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=1024),
        security=SecurityConfig(hmac_key=None),
        storage=StorageConfig(sqlite_path="/tmp/x.db"),
    )
    assert cfg.ui_enabled is True


def test_config_parses_ui_section(tmp_path):
    import yaml
    from mdrj.config import load_config
    cfg_path = tmp_path / "node.yaml"
    cfg_path.write_text(yaml.safe_dump({
        "node_id": "n", "listen": "127.0.0.1:0", "peers": [],
        "profile": {"role": "node", "memory_mb": 64, "bw_kbps": 256, "threat_level": "LOW"},
        "gossip": {"period_sec": 1.0, "fan_out": 1},
        "prioritization": {"level_threshold_B": "LOW", "max_batch_bytes": 1024},
        "security": {},
        "storage": {"sqlite_path": str(tmp_path / "n.db")},
        "ui": {"enabled": False},
    }), encoding="utf-8")
    cfg = load_config(cfg_path)
    assert cfg.ui_enabled is False


@pytest.mark.asyncio
async def test_headless_app_omits_ui_routes(tmp_path, aiohttp_client):
    from mdrj.api import build_app
    node = Node(_config(tmp_path, ui_enabled=False))
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        # UI-роуты отсутствуют → 404.
        assert (await client.get("/viz/graph")).status == 404
        assert (await client.get("/incidents")).status == 404
        assert (await client.post("/catalog/policy", json={})).status == 404
        assert (await client.get("/catalog")).status == 404
        # Inter-node роуты на месте.
        assert (await client.get("/status")).status == 200
        assert (await client.get("/gossip/frontier")).status == 200
        assert (await client.get("/metrics/prometheus")).status == 200
        assert (await client.get("/consensus/digest")).status == 200
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_headless_viz_returns_stub(tmp_path, aiohttp_client):
    from mdrj.api import build_app
    node = Node(_config(tmp_path, ui_enabled=False))
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.get("/viz")
        assert resp.status == 200
        text = await resp.text()
        assert "headless" in text.lower()
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_full_app_has_all_routes(tmp_path, aiohttp_client):
    from mdrj.api import build_app
    node = Node(_config(tmp_path, ui_enabled=True))
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        assert (await client.get("/viz/graph")).status == 200
        assert (await client.get("/catalog")).status == 200
        assert (await client.get("/status")).status == 200
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_status_reports_ui_enabled(tmp_path):
    node = Node(_config(tmp_path, ui_enabled=False))
    await node.start()
    try:
        assert node.status()["ui_enabled"] is False
    finally:
        await node.stop()
