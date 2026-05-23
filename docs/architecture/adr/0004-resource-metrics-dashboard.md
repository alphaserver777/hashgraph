# ADR-0004: Ресурсные метрики, история и дашборд

## Статус
Принято (этап 2 прототипа диссертационной работы). Готовит данные для эмпирической калибровки A4 в стохастической модели `diser_models/simulation.html`.

## Контекст
До этого решения `mdrj/metrics.py` отдавал только пять высокоуровневых индикаторов: `A_est`, `T_gossip`, `K_r`, `C_mem`, `C_net`. Этого достаточно для отладки госсипа, но **недостаточно** для двух важных диссертационных задач:

1. **Эмпирическая калибровка стохастической модели.** Для подстановки в `simulation.html` мне нужны измеримые ресурсные характеристики архитектуры A4: память (RSS процесса узла), размер хранилища (рост реестра), сетевой трафик (байт в секунду и байт на событие), latency от эмиссии до фиксации в total order. Без этих чисел невозможно сравнить A4 с A1/A2/A3 численно.
2. **Сравнение с SIEM-архитектурами.** В диссертации требуется численное сравнение по ресурсопотреблению. Поскольку SIEM работает на одном сервере с известными характеристиками, для p2p MDRJ-DAG нужно показывать сопоставимые метрики **на узел**.

Также для длительного анализа (24+ часа прогон) требуется временной ряд метрик, а не только текущий snapshot.

## Решение
Расширение метрик:
- В `mdrj/metrics.py:MetricsSnapshot` добавлены поля: `rss_bytes`, `cpu_percent` (через `psutil`), `db_size_bytes` (через `PRAGMA page_count*page_size`), `gossip_bytes_in_total`, `gossip_bytes_out_total`, `bytes_per_event`, `emit_to_consensus_latency_p50_ms`, `emit_to_consensus_latency_p95_ms`.
- Counter-семантика для `gossip_bytes_*_total` — монотонно растущие счётчики, удобные для Prometheus и для дельтового просмотра в дашборде (как сделано в JS дашборде).
- Hist для latency: `MetricsEngine._emit_to_consensus_latencies` — ring-buffer на 1000 наблюдений, отдаёт p50/p95 в миллисекундах.
- `Node.emit_event` теперь засекает `time.perf_counter()` перед началом и регистрирует latency после `_persist_envelope`. Метрика отражает **локальное** время от обращения к API до сохранения с consensus_ts; не покрывает сетевую репликацию.

История:
- Новая таблица `metrics_history(id, ts, snapshot_json)` в SQLite.
- Фоновый `_metrics_history_loop` в Node пишет snapshot каждые `_metrics_history_interval` секунд (по умолчанию 30 с). Periodic prune ограничивает количество строк до `_metrics_history_keep_rows` (по умолчанию 5760 ≈ 48 часов при 30-секундной частоте).
- CLI-friendly доступ через `Node.list_metrics_history(limit=N, since_ts=T)` и через HTTP `GET /metrics/history?limit=N&since=T`.

Endpoint'ы:
- `GET /metrics` — JSON snapshot (расширенный, обратно совместим).
- `GET /metrics/prometheus` — text/plain в формате Prometheus exposition. Каждой метрике задан тип (`gauge` или `counter`), labels `node_id`. Готово для скрейпа из Prometheus сервера, но также прямо читается человеком.
- `GET /metrics/history` — JSON временной ряд из `metrics_history`.
- `GET /metrics/dashboard` — HTML страница с Chart.js, тянет `/metrics` раз в 5 секунд и рисует 4 графика: RSS+DB size, network bytes (Δ), latency p50/p95, event_count+bytes_per_event. Внизу полный текущий snapshot в виде монопространственных «чипов».

Учёт байтов:
- `GossipEngine._send_to_peer` после успешного POST вызывает `metrics.record_gossip_out_bytes(len(body))`.
- `api.py:handle_event_batch` читает сырой body, вызывает `metrics.record_gossip_in_bytes(len(body))`, затем `json.loads(body)`. Body уже кеширован после HMAC middleware, второе чтение бесплатное.

## Последствия
**Положительные:**
- Узел теперь самостоятельно собирает все ресурсные характеристики, нужные для диссертации. После 24-часового прогона на 3-узловом кластере оператор скачивает `/metrics/history?limit=2880` и получает CSV-ready временной ряд.
- Prometheus-формат открывает дорогу к интеграции с Grafana / Alertmanager для long-running экспериментов.
- Дашборд готов к использованию без внешних зависимостей: только Chart.js с CDN. Никакого билдинга фронтенда.
- `bytes_per_event` напрямую сопоставим с `K_рес` в стохастической модели (затраты ресурсов).
- `emit_to_consensus_latency_p50_ms` — прямой прокси для скорости фиксации события, что калибрует P_сохр в модели.

**Отрицательные / ограничения:**
- **psutil — новая runtime-зависимость.** Добавлена в `pyproject.toml`. На Windows работает out-of-the-box, на Linux требует libc.
- **latency — локальная.** Метрика измеряет только local emit → local persist. Multi-node end-to-end latency (от emit на node1 до фиксации в total order на node2) не покрыта; для неё нужна корреляция timestamp'ов между узлами, что отдельная задача.
- **gossip_bytes_total counters обнуляются при `reset()`.** Это вызывается в `clear_events`. Для бенчмаркинга оператор должен помнить, что после clear `bytes_per_event` будет искажён.
- **metrics_history не реплицируется** между узлами. Это per-node ресурсный лог. Это правильно — каждый узел измеряет себя.
- **Dashboard fetches `/metrics` каждые 5 сек, не WebSocket.** Простота важнее. WebSocket-стрим — задача этапа 5 (Web UI auth).
- **Никаких графиков в `/metrics/dashboard` для классов событий A/B/C** — отображается общий event_count. Расширение разнесения по классам — отдельный шаг.

## См. также
- [ADR-0001](0001-event-kind-contract.md) — без явных event_kind метрики были бы привязаны к нелогичной классификации клиента.
- [ADR-0003](0003-collectors-package.md) — коллекторы инкрементируют event_count через `Node.emit_event`, что сразу попадает в эту систему метрик.
- [docs/devplan/devplan.md](../../devplan/devplan.md) этап 4 — финальная связка с UI-кабинетом и notifier.
- [diser_models/simulation.html](../../../../../diser_models/simulation.html) — целевая стохастическая модель, для калибровки которой эти метрики предназначены.
