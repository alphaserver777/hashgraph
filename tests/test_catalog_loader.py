"""Tests for JSON-based event catalog loader."""
from __future__ import annotations

import json
import sys

import pytest

from mdrj.event_catalog import (
    EVENT_CATALOG,
    all_event_metadata,
    catalog_title_for,
    event_class_for,
    event_metadata,
    is_known_event_kind,
)
from mdrj.models import EventClass


def test_json_catalog_is_loaded_on_import():
    """data/event_catalog.json должен подхватываться по умолчанию."""
    # Если JSON был найден, у нас должна быть метаинформация
    metadata = all_event_metadata()
    assert metadata, "metadata is empty — JSON-каталог не был загружен"
    # admin_ssh_login_success должен иметь rationale
    meta = event_metadata("admin_ssh_login_success")
    assert meta is not None
    assert "rationale" in meta
    assert meta["rationale"]  # непустое


def test_catalog_includes_lifecycle_events():
    """После Этапа service+host lifecycle новые типы должны быть в каталоге."""
    expected = {
        "mdrj_service_start",
        "mdrj_service_stop",
        "mdrj_service_killed",
        "host_boot",
        "host_reboot",
    }
    for kind in expected:
        assert is_known_event_kind(kind), f"{kind} не в каталоге"


def test_killed_is_class_a_and_explained():
    assert event_class_for("mdrj_service_killed") == EventClass.A
    meta = event_metadata("mdrj_service_killed")
    assert meta is not None
    assert "УБИ.124" in " ".join(str(t) for t in meta["linked_threats"])
    assert "kill" in meta["rationale"].lower() or "убит" in meta["rationale"].lower()


def test_unknown_event_kind_raises():
    with pytest.raises(KeyError):
        event_class_for("absolutely_nonexistent_kind")


def test_event_metadata_returns_none_for_unknown():
    assert event_metadata("absolutely_nonexistent_kind") is None


def test_title_is_russian_human_readable():
    title = catalog_title_for("admin_ssh_login_success")
    assert "SSH" in title or "SSH-вход" in title


@pytest.mark.asyncio
async def test_catalog_endpoint_returns_all_events(tmp_path, aiohttp_client):
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

    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    cfg = NodeConfig(
        node_id="catalog-test",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=None),
        storage=StorageConfig(sqlite_path=str(tmp_path / "n.db")),
        linux_ingest=LinuxIngestConfig(),
    )
    node = Node(cfg)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.get("/catalog")
        assert resp.status == 200
        data = await resp.json()
        assert data["version"] == 1
        assert data["count"] >= 15
        kinds = {item["event_kind"] for item in data["events"]}
        assert "admin_ssh_login_success" in kinds
        assert "mdrj_service_killed" in kinds

        # filter by class
        resp = await client.get("/catalog?class=A")
        a_data = await resp.json()
        assert all(item["class"] == "A" for item in a_data["events"])

        # filter by threat
        resp = await client.get("/catalog?threat=УБИ.124")
        threat_data = await resp.json()
        assert threat_data["count"] >= 1
        for item in threat_data["events"]:
            joined = " ".join(str(t) for t in item.get("linked_threats", []))
            assert "УБИ.124" in joined
    finally:
        await node.stop()
