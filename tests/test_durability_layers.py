"""Тесты четырёх слоёв надёжного сохранения улик.

Слой 1 — auto-propose checkpoint loop.
Слой 2 — ACK-fanout 2/3 для класса A.
Слой 3 — frontier anti-entropy (Hedera-стиль).
Слой 4 — фон-verify + tamper alert класса A.

Тесты на одном узле (без реальных пиров) — проверяют поведение,
конфигурацию и метаданные. End-to-end на кластере — на стенде.
"""
from __future__ import annotations

import asyncio
from typing import Optional

import pytest

from mdrj.config import (
    GossipConfig,
    HeartbeatConfig,
    LinuxIngestConfig,
    NodeConfig,
    PrioritizationConfig,
    RuntimeConfig,
    SecurityConfig,
    StorageConfig,
)
from mdrj.models import EventClass, NodeProfile
from mdrj.node import EventEmission, Node


def _config(tmp_path, *, runtime: Optional[RuntimeConfig] = None,
            hmac_key: Optional[str] = None) -> NodeConfig:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    return NodeConfig(
        node_id="durability-test",
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=hmac_key),
        storage=StorageConfig(sqlite_path=str(tmp_path / "node.db")),
        linux_ingest=LinuxIngestConfig(),
        heartbeat=HeartbeatConfig(),
        runtime=runtime or RuntimeConfig(),
    )


# ====================================================================
# RuntimeConfig — все новые поля по умолчанию выключены (обратная совмест.)
# ====================================================================

def test_runtime_defaults_disable_all_new_loops():
    cfg = RuntimeConfig()
    assert cfg.checkpoint_propose_interval_sec == 0.0
    assert cfg.frontier_sync_interval_sec == 0.0
    assert cfg.tamper_verify_interval_sec == 0.0
    assert cfg.class_a_fanout_quorum_ratio == 0.0


# ====================================================================
# Слой 1 — auto-propose checkpoint
# ====================================================================

@pytest.mark.asyncio
async def test_checkpoint_propose_loop_task_started_when_configured(tmp_path):
    cfg = _config(
        tmp_path,
        runtime=RuntimeConfig(checkpoint_propose_interval_sec=10.0),
        hmac_key="testkey",
    )
    node = Node(cfg)
    await node.start()
    try:
        assert node._checkpoint_propose_task is not None
        assert not node._checkpoint_propose_task.done()
    finally:
        await node.stop()
    # После stop задача должна корректно завершиться.
    assert node._checkpoint_propose_task is None


@pytest.mark.asyncio
async def test_checkpoint_propose_skipped_without_hmac(tmp_path):
    """Без security.hmac_key propose должен бережно skip-ать без crash."""
    cfg = _config(
        tmp_path,
        runtime=RuntimeConfig(checkpoint_propose_interval_sec=10.0),
        hmac_key=None,
    )
    node = Node(cfg)
    await node.start()
    try:
        # Прямой вызов одного шага — должен вернуть None, не упасть.
        result = await node._propose_one_checkpoint(margin=0)
        assert result is None
    finally:
        await node.stop()


# ====================================================================
# Слой 2 — ACK-fanout 2/3 для класса A
# ====================================================================

@pytest.mark.asyncio
async def test_class_a_solo_node_returns_local_only(tmp_path):
    """Одиночный узел без пиров — durability=local_only при включённом слое."""
    cfg = _config(
        tmp_path,
        runtime=RuntimeConfig(class_a_fanout_quorum_ratio=0.666,
                              class_a_fanout_timeout_sec=0.2,
                              class_a_fanout_max_retries=1),
        hmac_key="testkey",
    )
    node = Node(cfg)
    await node.start()
    try:
        emission: EventEmission = await node.emit_event(
            EventClass.A,
            {"event_kind": "virus", "host_id": "h", "node_id": "n"},
        )
        assert emission.stored is True
        assert emission.durability == "local_only"
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_class_a_with_quorum_disabled_returns_best_effort(tmp_path):
    """Если quorum_ratio=0 — старое поведение (durability=best_effort)."""
    cfg = _config(tmp_path, runtime=RuntimeConfig())
    node = Node(cfg)
    await node.start()
    try:
        emission = await node.emit_event(
            EventClass.A,
            {"event_kind": "virus", "host_id": "h", "node_id": "n"},
        )
        assert emission.durability == "best_effort"
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_class_b_durability_is_none(tmp_path):
    """События класса B не используют ACK-fanout — durability=None."""
    cfg = _config(tmp_path, runtime=RuntimeConfig(class_a_fanout_quorum_ratio=0.666))
    node = Node(cfg)
    await node.start()
    try:
        emission = await node.emit_event(
            EventClass.B,
            {"event_kind": "admin_login", "host_id": "h", "node_id": "n"},
        )
        assert emission.durability is None
    finally:
        await node.stop()


# ====================================================================
# Слой 3 — frontier endpoint + local_frontier()
# ====================================================================

@pytest.mark.asyncio
async def test_local_frontier_returns_latest_per_creator(tmp_path):
    """local_frontier() даёт по одному event_id на каждого creator."""
    cfg = _config(tmp_path)
    node = Node(cfg)
    await node.start()
    try:
        emission1 = await node.emit_event(EventClass.B, {"event_kind": "admin_login",
                                                          "host_id": "h", "node_id": "n", "marker": 1})
        emission2 = await node.emit_event(EventClass.B, {"event_kind": "admin_login",
                                                          "host_id": "h", "node_id": "n", "marker": 2})
        frontier = node.local_frontier()
        # Должна быть запись для нашего creator.
        assert cfg.node_id in frontier
        # И это именно второй (последний) event, не первый.
        assert frontier[cfg.node_id] == emission2.event.id
        assert frontier[cfg.node_id] != emission1.event.id
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_frontier_endpoint_returns_dict(tmp_path, aiohttp_client):
    """GET /gossip/frontier отдаёт JSON с полем 'frontier'."""
    from mdrj.api import build_app

    cfg = _config(tmp_path)
    node = Node(cfg)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.get("/gossip/frontier")
        assert resp.status == 200
        data = await resp.json()
        assert "frontier" in data
        assert isinstance(data["frontier"], dict)
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_ancestry_endpoint_returns_events(tmp_path, aiohttp_client):
    """GET /events/{id}/ancestry возвращает событие и его предков."""
    from mdrj.api import build_app

    cfg = _config(tmp_path)
    node = Node(cfg)
    await node.start()
    try:
        emission = await node.emit_event(EventClass.B,
                                         {"event_kind": "admin_login", "host_id": "h", "node_id": "n"})
        client = await aiohttp_client(build_app(node))
        resp = await client.get(f"/events/{emission.event.id}/ancestry?depth=8")
        assert resp.status == 200
        data = await resp.json()
        ids = {item["event"]["id"] for item in data["events"]}
        assert emission.event.id in ids
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_ancestry_unknown_event_returns_empty(tmp_path, aiohttp_client):
    from mdrj.api import build_app

    cfg = _config(tmp_path)
    node = Node(cfg)
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.get("/events/00deadbeef/ancestry")
        assert resp.status == 200
        data = await resp.json()
        assert data["events"] == []
    finally:
        await node.stop()


def test_ancestry_item_deserializes_to_envelope(tmp_path):
    """Регрессия: _pull_ancestry должен уметь разобрать ancestry-item
    обратно в Envelope. Раньше использовался несуществующий
    Event.from_dict → frontier sync падал на всём кластере, headless-узлы
    не могли догнать DAG."""
    from mdrj.models import Envelope, Event, EventClass

    ev = Event.create(
        cls_name=EventClass.A, source="n", ts_local=1.0, vclock={"n": 1},
        parents=[], creator="n", self_parent_id=None, other_parent_id=None,
        payload={"event_kind": "virus"},
    )
    # Формат, который отдаёт handle_event_ancestry.
    event_dict = ev.to_dict()
    event_dict["consensus_ts"] = ev.consensus_ts
    item = {"event": event_dict, "path_meta": [{"node": "n"}]}
    env = Envelope.from_dict(item)
    assert env.event.id == ev.id
    assert env.event.cls == EventClass.A
    assert env.path_meta == [{"node": "n"}]


# ====================================================================
# Слой 4 — tamper verify
# ====================================================================

@pytest.mark.asyncio
async def test_tamper_verify_skipped_without_checkpoints(tmp_path):
    """Без confirmed checkpoint фон-verify бережно возвращает None."""
    cfg = _config(
        tmp_path,
        runtime=RuntimeConfig(tamper_verify_interval_sec=10.0),
        hmac_key="testkey",
    )
    node = Node(cfg)
    await node.start()
    try:
        assert node._tamper_verify_task is not None
        # Прямой вызов одного шага — нет checkpoint, должен вернуть None.
        result = await node._verify_once_and_alert()
        assert result is None
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_tamper_alert_event_kind_in_catalog():
    """Новый класс A event_kind зарегистрирован в каталоге."""
    from mdrj.event_catalog import event_class_for, is_known_event_kind

    assert is_known_event_kind("mdrj_tamper_detected")
    assert event_class_for("mdrj_tamper_detected") == EventClass.A
    assert is_known_event_kind("mdrj_event_replication_failed")
    assert event_class_for("mdrj_event_replication_failed") == EventClass.B


# ====================================================================
# Prometheus extras — новые счётчики
# ====================================================================

@pytest.mark.asyncio
async def test_new_prometheus_counters_present(tmp_path):
    from mdrj.prometheus_extras import build_extras

    cfg = _config(tmp_path)
    node = Node(cfg)
    await node.start()
    try:
        series = build_extras(node)
        names = {s.name for s in series}
        assert "mdrj_class_a_durable_total" in names
        assert "mdrj_class_a_local_only_total" in names
        assert "mdrj_frontier_sync_pulls_total" in names
        assert "mdrj_tamper_alerts_total" in names
    finally:
        await node.stop()
