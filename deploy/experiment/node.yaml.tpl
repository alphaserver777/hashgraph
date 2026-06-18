node_id: __NODE_ID__
listen: 0.0.0.0:9002
peers:
__PEERS_BLOCK__

profile:
  # `responder` activates the incident workbench (kanban + checklist) in /viz.
  # Functionally equivalent to `node` for gossip and consensus.
  role: responder
  memory_mb: 128
  bw_kbps: 4096
  cpu_quota: 1.0
  threat_level: HIGH

gossip:
  period_sec: 1.0
  fan_out: 3

prioritization:
  level_threshold_B: LOW
  max_batch_bytes: 65536

security:
  hmac_key: __HMAC_KEY__

storage:
  sqlite_path: /var/lib/mdrj/node.db

# Legacy парсер /var/log/auth.log: эмитит admin_ssh_login_success (класс A)
# при каждом успешном SSH-входе. Это главный демонстрационный сигнал для
# диссертационного стенда. Реализован в mdrj/linux_ingest.py +
# mdrj/collectors/linux_auth.py. Через Слой 2 (ACK-fanout 2/3) событие
# гарантированно дойдёт до всех узлов.
linux_ingest:
  enabled: true
  source_type: auth_log_file
  auth_log_path: /var/log/auth.log
  poll_interval_sec: 2.0

collectors:
  audit:
    enabled: true
    poll_interval_sec: 30.0
  # firewall и proc генерят шум (iptables-save диффы, привилегированные
  # процессы systemd/cron) — десятки событий в минуту, /viz перегружается.
  # Включать только при целевых сценариях расследования.
  firewall:
    enabled: false
    poll_interval_sec: 10.0
  proc:
    enabled: false
    poll_interval_sec: 5.0

heartbeat:
  # Старый частый маячок — выключен. Заменён часовым диагностическим
  # снимком (runtime.hourly_status_interval_sec). Heartbeat можно
  # включить точечно для отладки.
  enabled: false
  interval_sec: 300.0

retention:
  enabled: true
  # 3 дня горячего хранения по запросу пользователя. Класс A — всегда,
  # класс B/C старше 3 дней удаляются (остаётся merkle-skeleton).
  max_age_days: 3
  keep_class_a: true
  poll_interval_sec: 300.0

# Параметры рантайма.
runtime:
  # Дебаунс пересчёта консенсуса. На слабых хостах 0.3-0.5 — K событий
  # в gossip-batch сольются в один пересчёт, x10 экономия по CPU и RSS.
  recompute_debounce_sec: 0.3

  # Слой 1 — auto-propose checkpoint каждые 10 мин. Без этого retention
  # никогда не сработает (checkpoint остаётся pending) и RSS растёт
  # линейно во времени до OOM.
  checkpoint_propose_interval_sec: 600
  checkpoint_propose_margin: 5

  # Слой 2 — ACK-fanout для класса A. При эмиссии события класса A
  # ждать ACK от ≥ 2/3 пиров за 10 секунд (3 повтора с backoff).
  # Если не собрали — эмитим mdrj_event_replication_failed (класс B)
  # и оставляем оригинал в _pending для долгого догона.
  class_a_fanout_quorum_ratio: 0.666
  class_a_fanout_timeout_sec: 10
  class_a_fanout_max_retries: 3

  # Слой 3 — frontier anti-entropy в стиле Hedera. Каждые 30 сек
  # сравниваем frontier (последний event_id на creator) со случайным
  # пиром и догоняем недостающее. Это делает удаление события на одном
  # узле физически невозможным при ≥ 1 честном пире.
  frontier_sync_interval_sec: 30

  # Слой 4 — фон-verify последнего confirmed checkpoint каждые 2 мин.
  # При обнаружении подделки эмитим класс A mdrj_tamper_detected,
  # который через Слой 2 гарантированно дойдёт до всех соседей.
  tamper_verify_interval_sec: 120

  # Часовой диагностический снимок (event_kind=node_hourly_status,
  # класс B). Замена частого heartbeat: вместо 12 пустых маячков в
  # час — одно событие с богатой диагностикой (uptime, коллекторы,
  # события по классам в окне, RSS, load_avg, последний checkpoint).
  hourly_status_interval_sec: 3600

discovery:
  mode: disabled

notifier:
  enabled: false

agent_relay:
  enabled: false
