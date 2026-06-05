#!/usr/bin/env bash
# Аварийное восстановление одного узла кластера, ушедшего в OOM-restart
# loop / зависание (sshd принимает connect, но не отдаёт banner).
#
# Скрипт:
#   1. Поллит SSH каждые SLEEP_SEC секунд до MAX_WAIT_SEC.
#   2. Как только SSH ответит — НЕМЕДЛЕННО глушит mdrj (брейк OOM-цикла).
#   3. Чистит DAG, обновляет код, пересоздаёт venv, кладёт свежий
#      systemd-юнит и конфиг (через install.sh для одного узла).
#   4. Проверяет /status и сравнивает membership_hash с другим живым узлом.
#
# Использование:
#   scripts/experiment/repair_node.sh <ssh-host> <peer1,peer2,peer3,...> <hmac-hex>
#
# Пример:
#   scripts/experiment/repair_node.sh Germany \
#     Germany,Germany2,Zomro,dev1-robots \
#     d04c8b1d824db922902bb0dc0ab6d6fa93e64a6ece9e9c91460df7206c457406
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <ssh-host> <peer1,peer2,...> <hmac-hex>"
  exit 2
fi

TARGET=$1
PEERS=$2
HMAC_KEY=$3

SLEEP_SEC=${SLEEP_SEC:-30}
MAX_WAIT_SEC=${MAX_WAIT_SEC:-7200}   # 2 часа максимум ждать

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Repair plan for $TARGET"
echo "    peers: $PEERS"
echo "    will poll SSH every ${SLEEP_SEC}s up to ${MAX_WAIT_SEC}s"
echo

START_TS=$(date +%s)
echo "==> [phase 1] Waiting for SSH on $TARGET ..."
until ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$TARGET" 'echo alive' >/dev/null 2>&1; do
  NOW=$(date +%s)
  ELAPSED=$((NOW - START_TS))
  if (( ELAPSED >= MAX_WAIT_SEC )); then
    echo "    SSH still unreachable after ${ELAPSED}s — giving up. Reboot the host via provider panel."
    exit 1
  fi
  printf '    %ds elapsed, retry in %ds...\n' "$ELAPSED" "$SLEEP_SEC"
  sleep "$SLEEP_SEC"
done
echo "==> SSH responded after $(( $(date +%s) - START_TS ))s"
echo

# Phase 2: emergency stop. ОЧЕНЬ важно сделать ПЕРВЫМ, иначе
# OOM-restart loop утопит хост обратно пока мы возимся с git pull.
echo "==> [phase 2] Emergency stop of mdrj on $TARGET"
ssh "$TARGET" 'systemctl stop mdrj 2>&1 || true; systemctl reset-failed mdrj 2>&1 || true; pkill -9 -f "mdrj.cli node" 2>/dev/null || true; sleep 2; systemctl is-active mdrj || true'
echo

# Phase 3: освободить память — выкинуть swap thrashing
echo "==> [phase 3] Drop caches + report memory state"
ssh "$TARGET" 'sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true; free -m | head -3; echo; uptime'
echo

# Phase 4: wipe DAG (предотвратить новый OOM после старта)
echo "==> [phase 4] Wipe local DAG on $TARGET"
ssh "$TARGET" 'rm -f /var/lib/mdrj/node.db /var/lib/mdrj/node.db-shm /var/lib/mdrj/node.db-wal && ls /var/lib/mdrj/ || true'
echo

# Phase 5: переустановить через стандартный install.sh — он сам сделает
# git pull, venv, новый unit с MemoryMax=2G, новый node.yaml.
echo "==> [phase 5] Run install.sh targeted at $TARGET only"
echo "    (install.sh резолвит peers через ssh — нужно чтобы остальные были живы)"
bash "$SCRIPT_DIR/install.sh" --peers "$PEERS" --hmac-key "$HMAC_KEY"
echo

# Phase 6: верификация
echo "==> [phase 6] Verify $TARGET joined the cluster"
sleep 10
ssh "$TARGET" 'curl -s http://localhost:9002/status' | python3 -c '
import json, sys
d = json.load(sys.stdin)
peers = [p["node_id"] for p in d["peers"] if not p["is_self"]]
print(f"  node_id={d[\"node_id\"]} state={d[\"state\"]}")
print(f"  epoch={d[\"consensus_epoch\"]} size={d[\"consensus_membership_size\"]}")
print(f"  hash={d[\"membership_snapshot_hash\"][:16]}")
print(f"  health={d[\"consensus_health\"]}")
print(f"  peers={peers}")
print(f"  event_count={d.get(\"event_count\",0)}")
'
echo
echo "==> Repair complete. Compare hash with another live node:"
echo "    ssh Germany2 'curl -s http://localhost:9002/status' | grep -o '\"membership_snapshot_hash\":\"[a-f0-9]*\"'"
