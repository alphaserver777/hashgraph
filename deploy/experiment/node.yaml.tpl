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

linux_ingest:
  enabled: false

collectors:
  audit:
    enabled: true
    poll_interval_sec: 5.0
  firewall:
    enabled: true
    poll_interval_sec: 10.0
  proc:
    enabled: true
    poll_interval_sec: 5.0

retention:
  enabled: true
  max_age_days: 7
  keep_class_a: true
  poll_interval_sec: 300.0

# Дебаунс пересчёта консенсуса. На слабых хостах поставить 0.3-0.5 —
# K событий в gossip-batch сольются в один пересчёт, экономия в x10
# по CPU и RSS. Цена: total_order отстаёт на window_sec.
runtime:
  recompute_debounce_sec: 0.3

discovery:
  mode: disabled

notifier:
  enabled: false

agent_relay:
  enabled: false
