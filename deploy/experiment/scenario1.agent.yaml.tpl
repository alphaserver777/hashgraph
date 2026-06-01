node_id: __NODE_ID__
listen: 0.0.0.0:9001
peers: []

profile:
  role: node
  memory_mb: 64
  bw_kbps: 4096
  cpu_quota: 1.0
  threat_level: HIGH

gossip:
  period_sec: 1.0
  fan_out: 0

prioritization:
  level_threshold_B: LOW
  max_batch_bytes: 65536

security:
  hmac_key: __HMAC_KEY__

storage:
  sqlite_path: /var/lib/mdrj/scenario1.db

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
  enabled: false

discovery:
  mode: disabled

notifier:
  enabled: false

agent_relay:
  enabled: true
  relay_url: __CENTRAL_URL__/event/emit
  timeout_sec: 5.0
  max_retries: 3
