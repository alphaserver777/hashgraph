#!/usr/bin/env bash
set -euo pipefail

NODES=${1:-3}
BASE_PORT=${BASE_PORT:-9001}
CONFIG_DIR=${CONFIG_DIR:-configs/demo}
LOG_DIR=${LOG_DIR:-logs}
mkdir -p "$CONFIG_DIR" "$LOG_DIR"

export NODES BASE_PORT CONFIG_DIR

python <<'PY'
import os
import yaml

nodes = int(os.environ.get("NODES", "3"))
base_port = int(os.environ.get("BASE_PORT", "9001"))
config_dir = os.environ.get("CONFIG_DIR", "configs/demo")
profiles = [
    {"role": "light", "memory_mb": 64, "bw_kbps": 128, "cpu_quota": 0.5, "threat_level": "LOW"},
    {"role": "medium", "memory_mb": 128, "bw_kbps": 256, "cpu_quota": 0.75, "threat_level": "ELEV"},
    {"role": "relay", "memory_mb": 256, "bw_kbps": 512, "cpu_quota": 1.0, "threat_level": "HIGH"},
]
ports = [base_port + idx for idx in range(nodes)]
for idx, port in enumerate(ports):
    peers = [f"127.0.0.1:{p}" for p in ports if p != port]
    profile = profiles[min(idx, len(profiles) - 1)]
    config = {
        "node_id": f"node-{idx+1}",
        "listen": f"127.0.0.1:{port}",
        "peers": peers,
        "profile": profile,
        "gossip": {"period_sec": 1.0, "fan_out": min(3, len(peers)) or 1},
        "prioritization": {"level_threshold_B": "ELEV", "max_batch_bytes": 32768},
        "security": {"hmac_key": "change-me"},
        "storage": {"sqlite_path": f"data/node{idx+1}.db"},
    }
    path = os.path.join(config_dir, f"node{idx+1}.yaml")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fp:
        yaml.safe_dump(config, fp)
PY

for idx in $(seq 1 "$NODES"); do
  cfg="$CONFIG_DIR/node${idx}.yaml"
  log="$LOG_DIR/node${idx}.log"
  echo "Starting node $idx using $cfg"
  (python -m mdrj.cli node --config "$cfg" >"$log" 2>&1 &) 
  sleep 0.2
done

echo "Cluster started. Tail logs in $LOG_DIR and use 'ps -ef | grep mdrj' to manage processes."
