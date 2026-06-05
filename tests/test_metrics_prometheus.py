"""Тесты расширенного /metrics/prometheus для диссертационных метрик."""
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
from mdrj.prometheus_extras import build_extras, render_series


def _config(tmp_path, *, node_id: str = "prom-test", heartbeat=None) -> NodeConfig:
    profile = NodeProfile(memory_mb=64, bw_kbps=256, cpu_quota=0.5, role="node", threat_level="HIGH")
    return NodeConfig(
        node_id=node_id,
        listen="127.0.0.1:0",
        peers=[],
        profile=profile,
        gossip=GossipConfig(period_sec=1.0, fan_out=1),
        prioritization=PrioritizationConfig(level_threshold_B="LOW", max_batch_bytes=65536),
        security=SecurityConfig(hmac_key=None),
        storage=StorageConfig(sqlite_path=str(tmp_path / "node.db")),
        linux_ingest=LinuxIngestConfig(),
        heartbeat=heartbeat or HeartbeatConfig(),
    )


def _series_by_name(series, name):
    return next((s for s in series if s.name == name), None)


def test_escape_label_in_render():
    from mdrj.prometheus_extras import MetricSample, MetricSeries

    serie = MetricSeries(
        name="mdrj_demo",
        type="gauge",
        help="demo",
        samples=[MetricSample(labels={"label": 'quote "x" \\ end'}, value=1.0)],
    )
    rendered = render_series([serie], common_labels={"node_id": "n1"})
    assert 'label="quote \\"x\\" \\\\ end"' in rendered
    assert 'node_id="n1"' in rendered
    assert "# TYPE mdrj_demo gauge" in rendered


@pytest.mark.asyncio
async def test_build_extras_baseline_on_fresh_node(tmp_path):
    """На свежем узле базовые серии присутствуют и обнулены."""
    node = Node(_config(tmp_path))
    await node.start()
    try:
        series = build_extras(node)
        names = {s.name for s in series}
        for required in (
            "mdrj_events_total",
            "mdrj_peers_total",
            "mdrj_peers_reachable",
            "mdrj_consensus_membership_size",
            "mdrj_quorum_size",
            "mdrj_heartbeat_emitted_total",
            "mdrj_service_started_total",
            "mdrj_service_stopped_total",
            "mdrj_service_killed_total",
            "mdrj_host_boot_total",
            "mdrj_host_reboot_total",
            "mdrj_checkpoint_confirmed_total",
            "mdrj_checkpoint_last_round",
            "mdrj_checkpoint_last_age_seconds",
            "mdrj_tamper_evidence",
        ):
            assert required in names, f"{required} отсутствует"

        # Без подтверждённых checkpoint метрика возраста = 0.
        last_age = _series_by_name(series, "mdrj_checkpoint_last_age_seconds")
        assert last_age.samples[0].value == 0.0

        # Tamper-evidence изначально 0.
        tamper = _series_by_name(series, "mdrj_tamper_evidence")
        assert tamper.samples[0].value == 0.0

        # service_started уже выросло на 1 после node.start().
        started = _series_by_name(series, "mdrj_service_started_total")
        assert started.samples[0].value == 1.0
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_events_counter_increments_on_emit(tmp_path):
    from mdrj.models import EventClass

    node = Node(_config(tmp_path))
    await node.start()
    try:
        baseline = build_extras(node)
        before = sum(s.value for s in _series_by_name(baseline, "mdrj_events_total").samples)
        await node.emit_event(EventClass.A, {"event_kind": "admin_ssh_login_success", "host_id": "h", "node_id": "n"})
        after_series = build_extras(node)
        after = sum(s.value for s in _series_by_name(after_series, "mdrj_events_total").samples)
        assert after == before + 1

        # Серия должна иметь sample с метками class=A, kind=admin_ssh_login_success.
        events_total = _series_by_name(after_series, "mdrj_events_total")
        found = [
            s for s in events_total.samples
            if s.labels.get("class") == "A" and s.labels.get("kind") == "admin_ssh_login_success"
        ]
        assert found and found[0].value >= 1.0
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_heartbeat_per_peer_age_present(tmp_path):
    cfg = _config(tmp_path, heartbeat=HeartbeatConfig(enabled=True, interval_sec=0.1))
    node = Node(cfg)
    await node.start()
    try:
        await asyncio.sleep(0.35)
        series = build_extras(node)
        hb_age = _series_by_name(series, "mdrj_heartbeat_last_seconds_ago")
        assert hb_age is not None
        # Должен быть хотя бы один sample для собственного node_id.
        own_samples = [s for s in hb_age.samples if s.labels.get("peer") == cfg.node_id]
        assert own_samples, "нет heartbeat-серии для собственного узла"
        # Возраст разумно мал (мы только что emit-нули).
        assert own_samples[0].value < 1.5
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_endpoint_returns_prometheus_format(tmp_path, aiohttp_client):
    from mdrj.api import build_app

    node = Node(_config(tmp_path))
    await node.start()
    try:
        client = await aiohttp_client(build_app(node))
        resp = await client.get("/metrics/prometheus")
        assert resp.status == 200
        body = await resp.text()
        # Базовая серия осталась.
        assert "mdrj_a_est" in body
        # Расширенные серии присутствуют.
        assert "mdrj_events_total" in body
        assert "mdrj_service_started_total" in body
        assert "mdrj_quorum_size" in body
        # node_id-метка задана.
        assert 'node_id="prom-test"' in body
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_service_started_counter_monotonic(tmp_path):
    """Counter mdrj_service_started_total должен расти, не уменьшаться."""
    node = Node(_config(tmp_path))
    await node.start()
    series1 = build_extras(node)
    v1 = _series_by_name(series1, "mdrj_service_started_total").samples[0].value
    # Повторная эмиссия start (как было бы при ручном вызове).
    await node._emit_service_start()
    series2 = build_extras(node)
    v2 = _series_by_name(series2, "mdrj_service_started_total").samples[0].value
    assert v2 > v1
    await node.stop()
