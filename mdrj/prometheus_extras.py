"""Расширенные Prometheus-серии для диссертационной задачи.

Эндпойнт `/metrics/prometheus` отдаёт два слоя:

1. Базовые поля `MetricsSnapshot` (gauge / counter) — отдаются как было.
2. Серии, собранные здесь — со своими метками (`class`, `kind`,
   `collector`, `peer`, `status`).

Связь с моделью диссертации:

* `mdrj_events_total{class,kind}`,
  `mdrj_events_by_collector_total{collector}` — слагаемые **K_d**
  (полнота сбора событий ИБ во времени).
* `mdrj_heartbeat_last_seconds_ago{peer}`, `mdrj_peers_reachable`,
  `mdrj_consensus_membership_size`, `mdrj_quorum_size` — слагаемые
  **P_save** (устойчивость регистрации события при отказах).
* `mdrj_service_killed_total`, `mdrj_tamper_evidence`,
  `mdrj_checkpoint_confirmed_total`, `mdrj_host_reboot_total` —
  индикаторы срабатывания 5 слоёв защиты от **УБИ.124**.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Tuple


Labels = Tuple[Tuple[str, str], ...]
"""Упорядоченный иммутабельный набор меток для одной выборки."""


@dataclass(slots=True)
class MetricSample:
    labels: Dict[str, str]
    value: float


@dataclass(slots=True)
class MetricSeries:
    name: str
    type: str  # "counter" | "gauge"
    help: str
    samples: List[MetricSample] = field(default_factory=list)


def _esc(value: str) -> str:
    """Экранирование значения метки по правилам Prometheus exposition format."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_series(series: Iterable[MetricSeries], common_labels: Mapping[str, str]) -> str:
    """Сериализовать список MetricSeries в text/plain exposition format."""
    lines: List[str] = []
    common_items = list(common_labels.items())
    for serie in series:
        lines.append(f"# HELP {serie.name} {serie.help}")
        lines.append(f"# TYPE {serie.name} {serie.type}")
        for sample in serie.samples:
            label_pairs = list(common_items) + list(sample.labels.items())
            if label_pairs:
                rendered = ",".join(f'{k}="{_esc(str(v))}"' for k, v in label_pairs)
                lines.append(f"{serie.name}{{{rendered}}} {sample.value}")
            else:
                lines.append(f"{serie.name} {sample.value}")
    return "\n".join(lines) + ("\n" if lines else "")


def build_extras(node) -> List[MetricSeries]:
    """Собрать все расширенные серии с заданного Node.

    Изолируется через утиную типизацию (без impоrt Node) — это позволяет
    переиспользовать функцию в тестах без полного запуска узла.
    """
    out: List[MetricSeries] = []

    # ---- Группа 1: события (K_d) -------------------------------------
    events_by_class = MetricSeries(
        name="mdrj_events_total",
        type="counter",
        help="Накопительный счётчик эмитированных событий по классу/типу",
    )
    for (cls, kind), count in sorted(node._events_by_class_kind.items()):
        events_by_class.samples.append(MetricSample(labels={"class": cls, "kind": kind}, value=count))
    if not events_by_class.samples:
        events_by_class.samples.append(MetricSample(labels={"class": "A", "kind": "_none"}, value=0))
    out.append(events_by_class)

    by_collector = MetricSeries(
        name="mdrj_events_by_collector_total",
        type="counter",
        help="События по коллектору-источнику",
    )
    enabled_gauge = MetricSeries(
        name="mdrj_collector_enabled",
        type="gauge",
        help="1 если коллектор включён и здоров, иначе 0",
    )
    last_poll = MetricSeries(
        name="mdrj_collector_last_poll_seconds_ago",
        type="gauge",
        help="Секунд с последнего успешного poll коллектора",
    )
    dropped = MetricSeries(
        name="mdrj_events_dropped_total",
        type="counter",
        help="Сколько событий было отброшено коллектором по причине",
    )
    now = time.time()
    for collector in getattr(node, "_collectors", []) or []:
        status = collector.status
        labels = {"collector": status.name}
        by_collector.samples.append(MetricSample(labels=labels, value=float(status.emitted_count)))
        enabled_gauge.samples.append(MetricSample(labels=labels, value=1.0 if status.enabled else 0.0))
        if status.last_poll_at is not None:
            last_poll.samples.append(MetricSample(labels=labels, value=max(0.0, now - float(status.last_poll_at))))
        if status.dropped_count:
            drop_labels = dict(labels)
            drop_labels["reason"] = status.last_drop_reason or "unknown"
            dropped.samples.append(MetricSample(labels=drop_labels, value=float(status.dropped_count)))
    for serie in (by_collector, enabled_gauge, last_poll, dropped):
        if serie.samples:
            out.append(serie)

    # ---- Группа 2: связность (P_save) --------------------------------
    peers_by_status: Dict[str, int] = {"approved": 0, "pending": 0, "rejected": 0}
    reachable = 0
    horizon = 30.0  # секунд: пир считается видимым если last_seen свежее
    try:
        registry_peers = node.list_peer_registry()
    except Exception:
        registry_peers = []
    for peer in registry_peers:
        status = getattr(peer, "approval_status", "approved") or "approved"
        peers_by_status[status] = peers_by_status.get(status, 0) + 1
        if not getattr(peer, "is_self", False):
            last_seen = getattr(peer, "last_seen", None)
            if last_seen is not None and (now - float(last_seen)) <= horizon:
                reachable += 1

    peers_total = MetricSeries(
        name="mdrj_peers_total",
        type="gauge",
        help="Пиров в peer-registry по статусу одобрения",
    )
    for status_name, count in peers_by_status.items():
        peers_total.samples.append(MetricSample(labels={"status": status_name}, value=float(count)))
    out.append(peers_total)

    out.append(MetricSeries(
        name="mdrj_peers_reachable",
        type="gauge",
        help=f"Пиров с last_seen < {horizon:.0f}c (внешние, без self)",
        samples=[MetricSample(labels={}, value=float(reachable))],
    ))

    membership = node.active_consensus_membership() or {}
    members = membership.get("members") or []
    membership_size = len(members)
    quorum_size = (2 * membership_size + 2) // 3  # ceil(2/3 * N)
    out.append(MetricSeries(
        name="mdrj_consensus_membership_size",
        type="gauge",
        help="Размер подтверждённого consensus-membership",
        samples=[MetricSample(labels={}, value=float(membership_size))],
    ))
    out.append(MetricSeries(
        name="mdrj_quorum_size",
        type="gauge",
        help="Размер кворума 2/3 для подписи checkpoint",
        samples=[MetricSample(labels={}, value=float(quorum_size))],
    ))

    # Heartbeat по пирам: последнее зафиксированное heartbeat-событие.
    hb_status = node.heartbeat_status()
    out.append(MetricSeries(
        name="mdrj_heartbeat_emitted_total",
        type="counter",
        help="Локальные heartbeat этого узла",
        samples=[MetricSample(labels={}, value=float(hb_status.get("emitted_count") or 0))],
    ))

    peer_heartbeats = _collect_peer_heartbeats(node)
    if peer_heartbeats:
        hb_series = MetricSeries(
            name="mdrj_heartbeat_last_seconds_ago",
            type="gauge",
            help="Секунд с последнего heartbeat-события от пира (включая себя)",
        )
        for peer_id, age in peer_heartbeats.items():
            hb_series.samples.append(MetricSample(labels={"peer": peer_id}, value=age))
        out.append(hb_series)

    # ---- Группа 3: слои защиты от УБИ.124 ----------------------------
    def counter(name: str, help_: str, value: float) -> MetricSeries:
        return MetricSeries(
            name=name,
            type="counter",
            help=help_,
            samples=[MetricSample(labels={}, value=float(value))],
        )

    out.append(counter("mdrj_service_started_total",
                      "Эмиссий mdrj_service_start с момента старта процесса",
                      getattr(node, "_service_started_count", 0)))
    out.append(counter("mdrj_service_stopped_total",
                      "Эмиссий mdrj_service_stop",
                      getattr(node, "_service_stopped_count", 0)))
    out.append(counter("mdrj_service_killed_total",
                      "Сколько раз обнаружен старт без предыдущего stop (улика УБИ.124)",
                      getattr(node, "_service_killed_count", 0)))
    out.append(counter("mdrj_host_boot_total",
                      "Зафиксированных загрузок ОС хоста",
                      getattr(node, "_host_boot_count", 0)))
    out.append(counter("mdrj_host_reboot_total",
                      "Зафиксированных перезагрузок ОС хоста",
                      getattr(node, "_host_reboot_count", 0)))
    out.append(counter("mdrj_checkpoint_confirmed_total",
                      "Сколько checkpoint достигли 2/3 кворума",
                      getattr(node, "_checkpoint_confirmed_count", 0)))
    # Слой 2 — durability эмиссий класса A.
    out.append(counter("mdrj_class_a_durable_total",
                      "Класс A с ACK ≥ 2/3 пиров (Слой 2)",
                      getattr(node, "_class_a_durable_count", 0)))
    out.append(counter("mdrj_class_a_local_only_total",
                      "Класс A без ACK 2/3 (упал в pending для догона)",
                      getattr(node, "_class_a_local_only_count", 0)))
    # Слой 3 — frontier anti-entropy.
    out.append(counter("mdrj_frontier_sync_pulls_total",
                      "События подтянутые через frontier-handshake",
                      getattr(node, "_frontier_sync_pulls_count", 0)))
    # Слой 4 — tamper alerts.
    out.append(counter("mdrj_tamper_alerts_total",
                      "Эмиссии mdrj_tamper_detected (улики подделки)",
                      getattr(node, "_tamper_alerts_count", 0)))

    last_round, last_age = _latest_checkpoint_metrics(node, now)
    out.append(MetricSeries(
        name="mdrj_checkpoint_last_round",
        type="gauge",
        help="round_received последнего confirmed checkpoint (0 если их нет)",
        samples=[MetricSample(labels={}, value=float(last_round))],
    ))
    out.append(MetricSeries(
        name="mdrj_checkpoint_last_age_seconds",
        type="gauge",
        help="Секунд с подтверждения последнего checkpoint",
        samples=[MetricSample(labels={}, value=float(last_age))],
    ))

    tamper = 1.0 if getattr(node, "_tamper_evidence", False) else 0.0
    out.append(MetricSeries(
        name="mdrj_tamper_evidence",
        type="gauge",
        help="1 если последний checkpoint/verify нашёл подделку, иначе 0",
        samples=[MetricSample(labels={}, value=tamper)],
    ))

    return out


def _collect_peer_heartbeats(node) -> Dict[str, float]:
    """Найти время последнего heartbeat-события на пира.

    Идём по событиям из storage с event_kind=heartbeat, берём ts_local
    последнего для каждого источника. Это даёт реальный «возраст»
    сигнала жизни как видит локальный узел, а не доверчивое last_seen
    из peer-registry.
    """
    now = time.time()
    latest: Dict[str, float] = {}
    try:
        events = node.storage.list_recent_events(limit=512)
    except Exception:
        return {}
    for event in events:
        payload = event.payload or {}
        if payload.get("event_kind") != "heartbeat":
            continue
        peer_id = str(payload.get("node_id") or event.source or "").strip()
        if not peer_id:
            continue
        ts = float(event.ts_local or 0.0)
        if ts > latest.get(peer_id, 0.0):
            latest[peer_id] = ts
    return {peer_id: max(0.0, now - ts) for peer_id, ts in latest.items()}


def _latest_checkpoint_metrics(node, now: float) -> Tuple[int, float]:
    """Возвращает (round_received, age_seconds) для последнего confirmed."""
    try:
        latest = node.storage.latest_confirmed_checkpoint()
    except Exception:
        return 0, 0.0
    if not latest:
        return 0, 0.0
    round_received = int(latest.get("round_received") or 0)
    confirmed_at = latest.get("confirmed_at") or latest.get("created_at") or 0
    age = max(0.0, now - float(confirmed_at))
    return round_received, age
