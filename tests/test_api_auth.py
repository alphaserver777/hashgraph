"""HMAC API auth middleware tests for Этап 0."""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import json

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
from mdrj.models import NodeProfile
from mdrj.node import Node

HMAC_KEY = "secret-key"


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
async def test_post_without_signature_when_key_configured_returns_401(tmp_path, aiohttp_client):
    cfg = _make_config(tmp_path, hmac_key=HMAC_KEY)
    node = Node(cfg)
    # Once users exist, the open-access fallback disappears and HMAC becomes mandatory.
    node.add_user(username="admin", password="pw", role="admin")
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.post("/event/emit", json={"cls": "C", "payload": {"note": "x"}})
        assert resp.status == 401
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_post_with_valid_signature_passes(tmp_path, aiohttp_client):
    cfg = _make_config(tmp_path, hmac_key=HMAC_KEY)
    node = Node(cfg)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        body = json.dumps({"cls": "C", "payload": {"note": "ok"}}).encode()
        sig = _sign(body, HMAC_KEY)
        resp = await client.post(
            "/event/emit",
            data=body,
            headers={"Content-Type": "application/json", "X-MDRJ-Sig": sig},
        )
        assert resp.status == 200
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_post_with_wrong_signature_returns_401(tmp_path, aiohttp_client):
    cfg = _make_config(tmp_path, hmac_key=HMAC_KEY)
    node = Node(cfg)
    node.add_user(username="admin", password="pw", role="admin")  # enable strict HMAC mode
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        body = json.dumps({"cls": "C", "payload": {}}).encode()
        resp = await client.post(
            "/event/emit",
            data=body,
            headers={"Content-Type": "application/json", "X-MDRJ-Sig": "0" * 64},
        )
        assert resp.status == 401
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_get_endpoints_never_require_signature(tmp_path, aiohttp_client):
    cfg = _make_config(tmp_path, hmac_key=HMAC_KEY)
    node = Node(cfg)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.get("/status")
        assert resp.status == 200
        resp = await client.get("/metrics")
        assert resp.status == 200
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_post_without_key_configured_is_unauthenticated(tmp_path, aiohttp_client):
    cfg = _make_config(tmp_path, hmac_key=None)
    node = Node(cfg)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.post("/event/emit", json={"cls": "C", "payload": {}})
        assert resp.status == 200
    finally:
        await node.stop()
