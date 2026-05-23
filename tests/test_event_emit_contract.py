"""Contract tests for the /event/emit endpoint after Этап 0 changes."""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import json

import pytest
from aiohttp import web

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


def _sign(body: bytes, key: str) -> str:
    return hmac_lib.new(key.encode(), body, hashlib.sha256).hexdigest()


@pytest.mark.asyncio
async def test_emit_with_event_kind_resolves_class_from_catalog(tmp_path, aiohttp_client):
    cfg = _make_config(tmp_path)
    node = Node(cfg)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        payload = {"event_kind": "admin_login_failure", "payload": {"user": "root", "source_ip": "10.0.0.1"}}
        resp = await client.post("/event/emit", json=payload)
        assert resp.status == 200
        data = await resp.json()
        assert data["event"]["cls"] == "A"
        assert data["event"]["payload"]["event_kind"] == "admin_login_failure"
        assert data["event"]["payload"]["user"] == "root"
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_emit_with_unknown_event_kind_returns_400(tmp_path, aiohttp_client):
    cfg = _make_config(tmp_path)
    node = Node(cfg)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.post("/event/emit", json={"event_kind": "definitely_not_in_catalog", "payload": {}})
        assert resp.status == 400
        assert "unknown event_kind" in (await resp.text())
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_emit_legacy_cls_path_still_works(tmp_path, aiohttp_client):
    cfg = _make_config(tmp_path)
    node = Node(cfg)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.post("/event/emit", json={"cls": "C", "payload": {"note": "legacy"}})
        assert resp.status == 200
        data = await resp.json()
        assert data["event"]["cls"] == "C"
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_emit_requires_event_kind_or_cls(tmp_path, aiohttp_client):
    cfg = _make_config(tmp_path)
    node = Node(cfg)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.post("/event/emit", json={"payload": {}})
        assert resp.status == 400
    finally:
        await node.stop()
