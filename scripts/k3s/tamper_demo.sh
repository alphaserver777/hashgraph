#!/usr/bin/env bash
# Tamper detection demo: modify one event's payload directly in the SQLite
# of one pod, then run /checkpoint/verify and show that the cluster
# immediately reports has_tamper_evidence=true.
#
# Prereqs:
#   - Cluster is up (deploy via scripts/k3s/deploy.sh).
#   - At least one /checkpoint/propose round has been triggered, so a
#     confirmed checkpoint exists.
#
# Usage:
#   scripts/k3s/tamper_demo.sh [--namespace mdrj] [--pod mdrj-3] [--target-round N]
set -euo pipefail

NAMESPACE=mdrj
POD=mdrj-3
TARGET_ROUND=""
HMAC_KEY=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --namespace) NAMESPACE=$2; shift 2;;
    --pod) POD=$2; shift 2;;
    --target-round) TARGET_ROUND=$2; shift 2;;
    --hmac-key) HMAC_KEY=$2; shift 2;;
    *) echo "unknown: $1"; exit 2;;
  esac
done

if [[ -z "$HMAC_KEY" ]]; then
  HMAC_KEY=$(kubectl -n "$NAMESPACE" get secret mdrj-secrets -o jsonpath='{.data.hmac-key}' | base64 -d)
fi

echo "=== Tamper demo on pod=${POD} ==="
echo ""

# Step 1: propose a checkpoint via $POD if no recent one exists.
echo "[1/4] Triggering checkpoint proposal on $POD"
sig=$(printf '{}' | openssl dgst -sha256 -hmac "$HMAC_KEY" | awk '{print $2}')
kubectl -n "$NAMESPACE" exec "$POD" -- curl -fsS -X POST \
  -H "Content-Type: application/json" \
  -H "X-MDRJ-Sig: $sig" \
  -d '{}' \
  http://localhost:9001/checkpoint/propose | python3 -m json.tool || true
echo ""

sleep 2

# Step 2: pick the round to verify
if [[ -z "$TARGET_ROUND" ]]; then
  TARGET_ROUND=$(kubectl -n "$NAMESPACE" exec "$POD" -- curl -fsS http://localhost:9001/checkpoint/list?status=confirmed \
    | python3 -c "import json,sys; data=json.load(sys.stdin); print(data['items'][0]['round_received'] if data.get('items') else 0)")
fi

echo "[2/4] Verifying checkpoint at round_received=${TARGET_ROUND} BEFORE tamper"
kubectl -n "$NAMESPACE" exec "$POD" -- curl -fsS \
  "http://localhost:9001/checkpoint/verify?round_received=${TARGET_ROUND}" | python3 -m json.tool

echo ""
echo "[3/4] Modifying ONE event's payload directly in SQLite on $POD"
kubectl -n "$NAMESPACE" exec "$POD" -- python3 -c "
import sqlite3
conn = sqlite3.connect('/data/node.db')
cur = conn.execute('SELECT id, payload FROM events WHERE round_received IS NOT NULL ORDER BY round_received DESC LIMIT 1')
row = cur.fetchone()
if not row:
    print('no events found')
else:
    eid, payload = row
    print(f'tampering event {eid[:16]}... original payload bytes: {len(payload)}')
    conn.execute('UPDATE events SET payload = ? WHERE id = ?', ('{\"tampered\": true}', eid))
    conn.commit()
    print('done')
"

echo ""
echo "[4/4] Verifying checkpoint at round_received=${TARGET_ROUND} AFTER tamper"
kubectl -n "$NAMESPACE" exec "$POD" -- curl -fsS \
  "http://localhost:9001/checkpoint/verify?round_received=${TARGET_ROUND}" | python3 -m json.tool

echo ""
echo "=== Done. Look for has_tamper_evidence: true in the second verify output. ==="
