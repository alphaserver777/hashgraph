"""Tests for Web UI authentication and role gating (Этап 5)."""
from __future__ import annotations

import time

import pytest

from mdrj.api import build_app
from mdrj.auth import (
    ROLE_ADMIN,
    ROLE_VIEWER,
    SESSION_COOKIE_NAME,
    SessionStore,
    hash_password,
    normalize_role,
    verify_password,
)
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


def _make_node(tmp_path, *, hmac_key=None) -> Node:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    cfg = NodeConfig(
        node_id="node-1",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=hmac_key),
        storage=StorageConfig(sqlite_path=str(tmp_path / "n.db")),
        linux_ingest=LinuxIngestConfig(),
    )
    return Node(cfg)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def test_hash_and_verify_roundtrip():
    hashed = hash_password("supersecret")
    assert verify_password("supersecret", hashed)
    assert not verify_password("wrong", hashed)


def test_hash_produces_different_salts():
    a = hash_password("same")
    b = hash_password("same")
    assert a != b  # random salt
    assert verify_password("same", a)
    assert verify_password("same", b)


def test_verify_rejects_malformed_hash():
    assert not verify_password("x", "not-a-hash")
    assert not verify_password("x", "scrypt$bad")


def test_normalize_role_falls_back_to_viewer():
    assert normalize_role("ADMIN") == ROLE_ADMIN
    assert normalize_role("Viewer") == ROLE_VIEWER
    assert normalize_role("unknown") == ROLE_VIEWER
    assert normalize_role(None) == ROLE_VIEWER


# ---------------------------------------------------------------------------
# SessionStore
# ---------------------------------------------------------------------------

def test_session_create_and_get():
    store = SessionStore(ttl_seconds=60)
    rec = store.create(username="alice", role=ROLE_ADMIN)
    fetched = store.get(rec.token)
    assert fetched is not None
    assert fetched.username == "alice"
    assert fetched.role == ROLE_ADMIN


def test_session_expires():
    store = SessionStore(ttl_seconds=1)
    rec = store.create(username="bob", role=ROLE_VIEWER)
    rec.expires_at = time.time() - 1  # backdate
    assert store.get(rec.token) is None


def test_session_revoke_user():
    store = SessionStore()
    a = store.create(username="carol", role=ROLE_ADMIN)
    b = store.create(username="carol", role=ROLE_ADMIN)
    other = store.create(username="dave", role=ROLE_VIEWER)
    assert store.revoke_user("carol") == 2
    assert store.get(a.token) is None
    assert store.get(b.token) is None
    assert store.get(other.token) is not None


# ---------------------------------------------------------------------------
# Node user management
# ---------------------------------------------------------------------------

def test_node_add_and_authenticate(tmp_path):
    node = _make_node(tmp_path)
    node.add_user(username="alice", password="pw1", role="admin")
    record = node.authenticate("alice", "pw1")
    assert record is not None
    assert record["role"] == ROLE_ADMIN
    assert node.authenticate("alice", "wrong") is None
    assert node.authenticate("unknown", "pw1") is None


def test_node_remove_user_revokes_sessions(tmp_path):
    node = _make_node(tmp_path)
    node.add_user(username="eve", password="pw", role="viewer")
    node.session_store.create(username="eve", role="viewer")
    assert len(node.session_store._sessions) == 1
    node.remove_user("eve")
    assert len(node.session_store._sessions) == 0


# ---------------------------------------------------------------------------
# HTTP login/role gating
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_open_access_when_no_users_configured(tmp_path, aiohttp_client):
    node = _make_node(tmp_path)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.get("/dag")
        assert resp.status == 200  # open, no users in DB
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_login_with_valid_credentials_sets_cookie(tmp_path, aiohttp_client):
    node = _make_node(tmp_path)
    node.add_user(username="admin1", password="pass", role="admin")
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.post("/auth/login", json={"username": "admin1", "password": "pass"})
        assert resp.status == 200
        assert SESSION_COOKIE_NAME in resp.cookies
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_login_with_invalid_credentials_401(tmp_path, aiohttp_client):
    node = _make_node(tmp_path)
    node.add_user(username="admin1", password="pass", role="admin")
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.post("/auth/login", json={"username": "admin1", "password": "wrong"})
        assert resp.status == 401
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_protected_endpoint_requires_login_when_users_exist(tmp_path, aiohttp_client):
    node = _make_node(tmp_path)
    node.add_user(username="someone", password="pw", role="viewer")
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        # Plain API client (Accept: */*) gets 401 JSON, not redirect
        resp = await client.get("/dag", headers={"Accept": "application/json"})
        assert resp.status == 401
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_viewer_cannot_run_write_endpoints(tmp_path, aiohttp_client):
    node = _make_node(tmp_path)
    node.add_user(username="viewer1", password="pw", role="viewer")
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        login = await client.post("/auth/login", json={"username": "viewer1", "password": "pw"})
        assert login.status == 200
        # Try to register a peer — viewers cannot
        resp = await client.post("/peers/register", json={"address": "10.0.0.1:9001"})
        assert resp.status == 403
        # But viewer CAN read metrics
        resp = await client.get("/metrics")
        assert resp.status == 200
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_admin_session_bypasses_hmac(tmp_path, aiohttp_client):
    node = _make_node(tmp_path, hmac_key="secret")
    node.add_user(username="root", password="pw", role="admin")
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        login = await client.post("/auth/login", json={"username": "root", "password": "pw"})
        assert login.status == 200
        # Admin session cookie should let us call /event/emit without X-MDRJ-Sig
        resp = await client.post("/event/emit", json={"cls": "C", "payload": {"k": 1}})
        assert resp.status == 200
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_logout_invalidates_session(tmp_path, aiohttp_client):
    node = _make_node(tmp_path)
    node.add_user(username="bob", password="pw", role="admin")
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        await client.post("/auth/login", json={"username": "bob", "password": "pw"})
        resp = await client.get("/auth/me")
        assert resp.status == 200
        await client.post("/auth/logout")
        resp = await client.get("/auth/me", headers={"Accept": "application/json"})
        assert resp.status == 401
    finally:
        await node.stop()
