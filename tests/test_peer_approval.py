"""Tests for peer approval workflow (Этап 4)."""
from __future__ import annotations

import asyncio
import json
from typing import List

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
from mdrj.discovery import (
    DiscoveredPeer,
    DiscoveryConfig,
    KubernetesDNSDiscovery,
    build_discovery,
)
from mdrj.models import (
    PEER_APPROVAL_APPROVED,
    PEER_APPROVAL_PENDING,
    PEER_APPROVAL_REJECTED,
    NodeProfile,
)
from mdrj.node import Node


def _make_node(tmp_path) -> Node:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    cfg = NodeConfig(
        node_id="node-1",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=None),
        storage=StorageConfig(sqlite_path=str(tmp_path / "n.db")),
        linux_ingest=LinuxIngestConfig(),
    )
    return Node(cfg)


def test_manual_registration_auto_approves(tmp_path):
    node = _make_node(tmp_path)
    node.register_peer("10.0.0.5:9001", note="manual", source="ui", node_id="peer-2")
    peer = next(p for p in node.storage.list_peers() if p.address == "10.0.0.5:9001")
    assert peer.approval_status == PEER_APPROVAL_APPROVED


def test_discovery_registration_is_pending(tmp_path):
    node = _make_node(tmp_path)
    node.register_peer(
        "10.0.0.6:9001",
        source="mdns",
        node_id="peer-3",
    )
    peer = next(p for p in node.storage.list_peers() if p.address == "10.0.0.6:9001")
    assert peer.approval_status == PEER_APPROVAL_PENDING


def test_pending_peer_is_not_in_active_gossip_set(tmp_path):
    node = _make_node(tmp_path)
    node.register_peer("10.0.0.7:9001", source="mdns", node_id="peer-4")
    # Active peers list (used for gossip) should NOT include pending peer
    assert "10.0.0.7:9001" not in {p.address for p in node.list_peers()}
    # But registry list (admin UI) SHOULD include it
    assert "10.0.0.7:9001" in {p.address for p in node.storage.list_peers()}


def test_approve_peer_moves_to_active(tmp_path):
    node = _make_node(tmp_path)
    node.register_peer("10.0.0.8:9001", source="mdns", node_id="peer-5")
    assert "10.0.0.8:9001" not in {p.address for p in node.list_peers()}
    node.approve_peer("10.0.0.8:9001")
    assert "10.0.0.8:9001" in {p.address for p in node.list_peers()}


def test_reject_peer_stays_out_of_active(tmp_path):
    node = _make_node(tmp_path)
    node.register_peer("10.0.0.9:9001", source="mdns", node_id="peer-6")
    node.reject_peer("10.0.0.9:9001")
    peer = next(p for p in node.storage.list_peers() if p.address == "10.0.0.9:9001")
    assert peer.approval_status == PEER_APPROVAL_REJECTED
    assert "10.0.0.9:9001" not in {p.address for p in node.list_peers()}


@pytest.mark.asyncio
async def test_api_approve_endpoint(tmp_path, aiohttp_client):
    node = _make_node(tmp_path)
    node.register_peer("10.0.0.10:9001", source="mdns", node_id="peer-7")
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.post("/peers/approve", json={"address": "10.0.0.10:9001"})
        assert resp.status == 200
        body = await resp.json()
        assert body["peer"]["approval_status"] == PEER_APPROVAL_APPROVED
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_api_reject_unknown_peer_returns_404(tmp_path, aiohttp_client):
    node = _make_node(tmp_path)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.post("/peers/reject", json={"address": "nope:1234"})
        assert resp.status == 404
    finally:
        await node.stop()


def test_existing_pre_stage4_peers_keep_working(tmp_path):
    """Backward-compat: peers inserted before Stage 4 must default to approved."""
    node = _make_node(tmp_path)
    # Direct insert bypassing the new approval_status parameter
    node.storage._conn.execute(
        "INSERT INTO peers(address, node_id, last_seen, healthy, enabled, note, source, role) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("10.0.0.99:9001", "old-peer", 0.0, 1, 1, "", "config", "node"),
    )
    node.storage._conn.commit()
    # The schema-migration sweep should leave them as 'approved' (column DEFAULT)
    peer = next(p for p in node.storage.list_peers() if p.address == "10.0.0.99:9001")
    assert peer.approval_status == PEER_APPROVAL_APPROVED


def test_kubernetes_dns_discovery_resolves_via_callback(tmp_path):
    """KubernetesDNSDiscovery should call on_peer for every resolved IP."""
    discovered: List[str] = []

    async def on_peer(addr, node_id, source):
        discovered.append(f"{addr}|{source}")

    class FakeK8sDiscovery(KubernetesDNSDiscovery):
        def _resolve_service(self):
            return [
                DiscoveredPeer(address="10.42.0.5:9001"),
                DiscoveredPeer(address="10.42.0.6:9001"),
                DiscoveredPeer(address="10.42.0.7:9001"),
            ]

    backend = FakeK8sDiscovery(
        service="mdrj-headless.mdrj.svc",
        target_port=9001,
        node_id="self",
        on_peer=on_peer,
        poll_interval_sec=0.1,
        self_address="127.0.0.1:9001",
    )

    async def run():
        await backend.start()
        await asyncio.sleep(0.15)
        await backend.stop()

    asyncio.run(run())
    assert len(discovered) == 3
    assert all(d.endswith("|k8s") for d in discovered)


def test_build_discovery_returns_none_when_disabled():
    cfg = DiscoveryConfig(mode="disabled")
    backend = build_discovery(
        config=cfg, node_id="x", listen="127.0.0.1:9001", on_peer=lambda *a, **kw: None  # type: ignore[arg-type]
    )
    assert backend is None


def test_build_discovery_returns_none_for_k8s_without_service():
    cfg = DiscoveryConfig(mode="k8s")  # no k8s_service
    backend = build_discovery(
        config=cfg, node_id="x", listen="127.0.0.1:9001", on_peer=lambda *a, **kw: None  # type: ignore[arg-type]
    )
    assert backend is None
