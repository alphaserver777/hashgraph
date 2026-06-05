# Соответствие runtime-метрик прототипа переменным стохастической модели

Этот документ — мост между двумя артефактами диссертации:

- **Стохастическая модель** в `diser_models/simulation.html`, которая
  сравнивает архитектуры A1 (SIEM standalone), A2 (SIEM + горячий
  резерв), A3 (SIEM + холодный резерв), A4 (НАГ-реестр) по целевой
  функции

  $$\Omega = \frac{K_d \cdot P_{\text{сохр}}}{K_{\text{рес}}} \;\to\; \max,
  \qquad K_{\text{рес}} \le R_{\max}=1, \quad K_d = 1.$$

- **Работающий прототип MDRJ-DAG** (см. [`hashgraph/`](../../hashgraph/)),
  который во время эксперимента эмитит реальные сигналы ИБ на трёх
  узлах и отдаёт Prometheus-метрики через `/metrics/prometheus`.

Цель — подставить эмпирически измеренные значения K_d, P_сохр, K_рес
из стенда в раздел «Сценарий ресурсного измерения» симулятора как
калибровку A4. Без таблицы ниже формулы модели и серии Prometheus
живут параллельно и не доказывают друг друга.

## Свод соответствий

| Переменная модели | Что значит | Серия Prometheus | PromQL-формула на работающем стенде |
|---|---|---|---|
| `K_d` (НАГ, A4) | Доля собранных и сохранённых событий ИБ | `mdrj_events_total{class,kind}` | `sum(rate(mdrj_events_total{class=~"A\|B"}[5m])) / sum(rate(mdrj_events_total[5m]))` — доля A/B-классов от всего потока |
| `K_d` по коллектору | Вклад каждого источника в полноту сбора | `mdrj_events_by_collector_total{collector}` | `sum by (collector) (rate(mdrj_events_by_collector_total[5m]))` |
| Полнота сбора как 1 − loss | Сколько отбрасывается фильтром / parser-ошибкой | `mdrj_events_dropped_total{collector,reason}` | `1 - sum(rate(mdrj_events_dropped_total[5m])) / (sum(rate(mdrj_events_dropped_total[5m])) + sum(rate(mdrj_events_total[5m])))` |
| `P_сохр` (вероятность сохранения) | Шанс что событие переживёт vector атак | `mdrj_peers_reachable`, `mdrj_quorum_size` | `min(mdrj_peers_reachable) / mdrj_quorum_size` — поддерживается ли кворум во времени |
| `P_сохр` (живучесть узлов) | Без heartbeat пиров считаются «упавшими» | `mdrj_heartbeat_last_seconds_ago{peer}` | `count(mdrj_heartbeat_last_seconds_ago < 30)` — сколько узлов «живы» за последние 30c |
| `K_рес` (нагрузка) | Ресурсопотребление одной ноды | `mdrj_rss_bytes`, `mdrj_cpu_percent`, `mdrj_db_size_bytes` | `avg(mdrj_rss_bytes) / (R_max_bytes)`, `avg(mdrj_cpu_percent)/100`, `avg(mdrj_db_size_bytes)/R_db_max` |
| `K_рес` (сетевая) | Сколько байтов gossip на одно событие | `mdrj_bytes_per_event` | `avg(mdrj_bytes_per_event)` — в диссертации делим на пропускную способность канала |
| Латентность доставки | Аналог `τ_recover` модели A3 | `mdrj_emit_to_consensus_latency_p95_ms` | `histogram_quantile(0.95, ...)` или прямое чтение |
| `Ω` (целевая) | Сводный показатель | вычисляется в Графане | `(K_d_realtime * P_save_realtime) / K_res_realtime` через `record:` rules |

## Соответствие 5 слоёв защиты УБИ.124 → серии Prometheus

Стохастическая модель оценивает P_сохр без явной модели атаки;
прототип демонстрирует **конкретные срабатывания** защиты. Чтобы
эмпирический результат можно было приложить к разделу диссертации
«УБИ.124», каждый слой даёт измеримый сигнал:

| Слой | Что защищает | Серия | Сигнал срабатывания |
|---|---|---|---|
| 1. Merkle + checkpoint | Подделка SQLite-записей | `mdrj_tamper_evidence` | `== 1` после `/checkpoint/verify` нашёл расхождение |
| 2. Heartbeat класса C | Тихое прерывание сбора | `mdrj_heartbeat_last_seconds_ago{peer}` | `> 2 * interval_sec` для конкретного пира |
| 3. service_lifecycle (start/stop/killed) | kill -9, OOM, crash | `mdrj_service_killed_total` | `increase(mdrj_service_killed_total[1h]) > 0` |
| 4. host_lifecycle (boot/reboot) | Подмена unit-файла / скрытый ребут | `mdrj_host_reboot_total` | `increase(mdrj_host_reboot_total[1h]) > 0` |
| 5. Кворум ≥ 2/3 для подписи | Сговор N−1 пиров | `mdrj_quorum_size`, `mdrj_consensus_membership_size` | `mdrj_checkpoint_confirmed_total` не растёт при `mdrj_peers_reachable < mdrj_quorum_size` |

## Как использовать в защите

1. На стенде запустить 24-часовой прогон с реалистичной нагрузкой
   (heartbeat класс C каждые 5 мин + случайные admin_ssh события).
2. Прометеус (на отдельном VDS, не на узлах) скрапит
   `/metrics/prometheus` каждые 15 сек со всех 3 узлов
   (`deploy/prometheus/mdrj-targets.yml`).
3. Графана импортирует `deploy/grafana/mdrj-dashboard.json` —
   4 панели соответствуют 4 группам таблицы выше.
4. В диссертационный текст идут:
   - Скриншот «Слои защиты УБИ.124»: момент подделки события →
     `mdrj_tamper_evidence` подскочил с 0 до 1.
   - Скриншот «P_save при отказе узла»: `systemctl stop mdrj` на
     одном из 3 — `mdrj_peers_reachable` упал с 3 до 2, кворум 2/3
     сохранён, кластер живой.
   - CSV-экспорт `mdrj_rss_bytes` / `mdrj_db_size_bytes` /
     `mdrj_bytes_per_event` → подставляется в `simulation.html`
     как ground-truth для калибровки A4.

## Открытые ограничения замеров

- На стенде 3 узла; кворум 2 — модель симулятора рассматривает
  N → ∞. Перенос результата на «большой кластер» требует отдельной
  главы про масштабирование (в работе предполагается линейная
  деградация bytes_per_event при добавлении gossip-fan-out).
- `mdrj_tamper_evidence` — gauge, а не event: она сбрасывается
  следующим успешным `/checkpoint/verify`. Для гарантированной
  фиксации факта подделки используйте `increase(...)` на
  Prometheus alert rule (см. `deploy/prometheus/alerts.yml`).
- `K_d` на стенде < 1 (есть фильтр класса C и не-критичных событий).
  Это и есть ожидаемая характеристика A4 — селективная
  классификация. Модель отражает это коэффициентом `dec-Kd4` ≈ 0.97;
  стендовое значение нужно подставить в этот вход.
