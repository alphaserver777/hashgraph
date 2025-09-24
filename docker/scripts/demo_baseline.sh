#!/bin/bash
set -euo pipefail

wait_for() {
  local host=$1
  local port=$2
  echo "Waiting for ${host}:${port} ..."
  until curl -fsS "http://${host}:${port}/status" >/dev/null 2>&1; do
    sleep 1
  done
  echo "${host}:${port} is ready"
}

wait_for node1 9001
wait_for node2 9002
wait_for node3 9003

# Emit baseline events across the cluster
python -m mdrj.cli emit --config /app/docker/configs/node1.yaml --cls A --api node1:9001 >/tmp/emit1.json

cat <<JSON >/tmp/payload.json
{"source_ip": "10.20.0.5", "action": "alert", "severity": "high"}
JSON
python -m mdrj.cli emit --config /app/docker/configs/node2.yaml --cls B --payload /tmp/payload.json --api node2:9002 >/tmp/emit2.json

python -m mdrj.cli metrics --config /app/docker/configs/node1.yaml --api node1:9001
python -m mdrj.cli metrics --config /app/docker/configs/node2.yaml --api node2:9002
python -m mdrj.cli metrics --config /app/docker/configs/node3.yaml --api node3:9003

echo "Baseline demo complete. Emitted events:"
cat /tmp/emit1.json
cat /tmp/emit2.json
