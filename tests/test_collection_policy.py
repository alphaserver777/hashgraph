"""Тесты политики сбора СИБ (ось 3: registry_enabled) + новые парсеры."""
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
from mdrj.event_catalog import (
    collection_policy_hash,
    registry_enabled_for,
    set_registry_enabled,
)
from mdrj.models import EventClass, NodeProfile
from mdrj.node import Node


def _config(tmp_path) -> NodeConfig:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    return NodeConfig(
        node_id="policy-test",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=None),
        storage=StorageConfig(sqlite_path=str(tmp_path / "node.db")),
        linux_ingest=LinuxIngestConfig(),
    )


# ---- Каталог: новые поля и события ---------------------------------

def test_new_events_registered():
    from mdrj.event_catalog import event_class_for, is_known_event_kind
    for kind in ("privilege_escalation", "user_account_created", "log_cleared",
                 "audit_config_changed", "security_service_failure",
                 "mdrj_collection_policy_changed"):
        assert is_known_event_kind(kind), kind
    assert event_class_for("log_cleared") == EventClass.A


def test_registry_enabled_default_true():
    assert registry_enabled_for("log_cleared") is True
    # Неизвестный тип — тоже True (не теряем случайно).
    assert registry_enabled_for("totally_unknown") is True


def test_policy_hash_changes_with_toggle():
    h1 = collection_policy_hash()
    set_registry_enabled("portscan", False)
    h2 = collection_policy_hash()
    assert h1 != h2
    set_registry_enabled("portscan", True)  # вернуть
    assert collection_policy_hash() == h1


# ---- Node.set_collection_policy ------------------------------------

@pytest.mark.asyncio
async def test_set_policy_emits_class_a_evidence(tmp_path):
    node = Node(_config(tmp_path))
    await node.start()
    try:
        result = await node.set_collection_policy("portscan", False)
        assert result["new_enabled"] is False
        assert registry_enabled_for("portscan") is False
        # Эмитировано событие mdrj_collection_policy_changed класса A.
        evs = [e for e in node.storage.all_events()
               if (e.payload or {}).get("event_kind") == "mdrj_collection_policy_changed"]
        assert len(evs) == 1
        assert evs[0].cls == EventClass.A
        assert (evs[0].payload or {}).get("changed_kind") == "portscan"
    finally:
        set_registry_enabled("portscan", True)
        await node.stop()


@pytest.mark.asyncio
async def test_protected_kinds_cannot_be_disabled(tmp_path):
    node = Node(_config(tmp_path))
    await node.start()
    try:
        with pytest.raises(ValueError):
            await node.set_collection_policy("node_hourly_status", False)
        with pytest.raises(ValueError):
            await node.set_collection_policy("mdrj_tamper_detected", False)
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_unknown_kind_raises(tmp_path):
    node = Node(_config(tmp_path))
    await node.start()
    try:
        with pytest.raises(KeyError):
            await node.set_collection_policy("no_such_kind", False)
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_policy_hash_in_hourly_status(tmp_path):
    from mdrj.config import RuntimeConfig
    cfg = _config(tmp_path)
    cfg.runtime = RuntimeConfig(hourly_status_interval_sec=70.0)
    node = Node(cfg)
    await node.start()
    try:
        await node._emit_hourly_status()
        evs = [e for e in node.storage.all_events()
               if (e.payload or {}).get("event_kind") == "node_hourly_status"]
        assert evs
        assert "collection_policy_hash" in (evs[-1].payload or {})
    finally:
        await node.stop()


# ---- API endpoint --------------------------------------------------

@pytest.mark.asyncio
async def test_catalog_endpoint_exposes_policy_fields(tmp_path, aiohttp_client):
    from mdrj.api import build_app
    node = Node(_config(tmp_path))
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.get("/catalog")
        data = await resp.json()
        item = next(e for e in data["events"] if e["event_kind"] == "log_cleared")
        assert "npa" in item and item["npa"]
        assert "registry_enabled" in item
        assert "protected" in item
        # Служебное событие помечено protected.
        prot = next(e for e in data["events"] if e["event_kind"] == "node_hourly_status")
        assert prot["protected"] is True
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_policy_endpoint_toggles(tmp_path, aiohttp_client):
    from mdrj.api import build_app
    node = Node(_config(tmp_path))
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.post("/catalog/policy",
                                 json={"event_kind": "portscan", "enabled": False})
        assert resp.status == 200
        data = await resp.json()
        assert data["new_enabled"] is False
        # Защищённое (есть в каталоге, но protected) — 403.
        resp2 = await client.post("/catalog/policy",
                                  json={"event_kind": "mdrj_tamper_detected", "enabled": False})
        assert resp2.status == 403
    finally:
        set_registry_enabled("portscan", True)
        await node.stop()


# ---- Парсеры linux_ingest ------------------------------------------

def test_failed_burst_parser(tmp_path):
    from mdrj.linux_ingest import LinuxAuthLogIngestor
    cfg = LinuxIngestConfig(enabled=True, auth_log_path=str(tmp_path / "auth.log"))
    ing = LinuxAuthLogIngestor(config=cfg, node_id="n", default_state_path=str(tmp_path / "st.json"))
    base = "2026-06-18T10:00:0%d+00:00 host sshd[1]: Failed password for invalid user x from 9.9.9.9 port 22 ssh2"
    results = []
    for i in range(6):
        r = ing._parse_other(base % i, i, 1000.0 + i)
        if r is not None:
            results.append(r)
    # При пороге 5 ровно один burst должен сработать в серии из 6 fail.
    bursts = [r for r in results if r["event_kind"] == "failed_login_burst"]
    assert len(bursts) == 1
    assert bursts[0]["source_ip"] == "9.9.9.9"
    assert bursts[0]["failed_count"] >= 5


def test_privilege_escalation_parser(tmp_path):
    from mdrj.linux_ingest import LinuxAuthLogIngestor
    cfg = LinuxIngestConfig(enabled=True, auth_log_path=str(tmp_path / "auth.log"))
    ing = LinuxAuthLogIngestor(config=cfg, node_id="n", default_state_path=str(tmp_path / "st.json"))
    line = "Jun 18 10:00:01 host sudo[9]: pam_unix(sudo:session): session opened for user root(uid=0) by admin(uid=1000)"
    out = ing._parse_other(line, 0, 1000.0)
    assert out is not None
    assert out["event_kind"] == "privilege_escalation"
    assert out["mechanism"] == "sudo"
    assert out["target_user"] == "root"
