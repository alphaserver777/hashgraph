#!/usr/bin/env bash
# Аварийный low-memory режим для Germany (хост с ~600M свободного RAM,
# на котором уже крутятся dockerd / syncthing / alloy).
#
# Что делает (всё через ОДНУ ssh-сессию пока хост откликается):
#   1. Сразу стопит mdrj и систему рестартов.
#   2. Кладёт systemd-override с MemoryMax=384M (вместо общего 2G).
#   3. Включает в /etc/mdrj/node.yaml жёсткий runtime-дебаунс 1.0 c и
#      отключает heartbeat (не критично для UI, экономит cycles).
#   4. Чистит DAG и стартует mdrj.
#
# Запуск ПОСЛЕ перезагрузки Germany через панель хостера (или после того
# как ОС сама выйдет из swap-thrash):
#
#   scripts/experiment/repair_germany_lowmem.sh Germany
set -euo pipefail

TARGET=${1:-Germany}

echo "==> Waiting for SSH on $TARGET (Ctrl-C if надоело ждать)..."
until ssh -o BatchMode=yes -o ConnectTimeout=10 "$TARGET" 'echo alive' >/dev/null 2>&1; do
  sleep 20
  printf '.'
done
echo
echo "==> SSH responded"

echo "==> Emergency stop mdrj + reset failure limit"
ssh "$TARGET" 'set -e
systemctl stop mdrj 2>&1 || true
systemctl reset-failed mdrj 2>&1 || true
pkill -9 -f "mdrj.cli node" 2>/dev/null || true
sleep 2'

echo "==> Apply low-memory systemd override (MemoryMax=384M, MemorySwapMax=0)"
ssh "$TARGET" 'mkdir -p /etc/systemd/system/mdrj.service.d/ && cat > /etc/systemd/system/mdrj.service.d/low-memory.conf <<EOF
[Service]
# Override для слабого хоста: 384M из 1.9G физических ОЗУ.
# MemorySwapMax=0 — запрещаем swap чтобы не уходить в thrashing.
MemoryMax=384M
MemorySwapMax=0
# StartLimitBurst=3 — если упадём 3 раза подряд за StartLimitIntervalSec,
# systemd прекратит перезапуск и переведёт unit в failed. Защита от
# OOM-loop, который топит весь хост.
EOF
echo "wrote override:"
cat /etc/systemd/system/mdrj.service.d/low-memory.conf'

# Глобальный StartLimitBurst идёт в Unit, не Service — отдельный override
ssh "$TARGET" 'cat > /etc/systemd/system/mdrj.service.d/restart-limit.conf <<EOF
[Unit]
StartLimitIntervalSec=120
StartLimitBurst=3
EOF
systemctl daemon-reload'

echo "==> Aggressive debounce in node.yaml (1.0s)"
ssh "$TARGET" "sed -i 's/recompute_debounce_sec:.*/recompute_debounce_sec: 1.0/' /etc/mdrj/node.yaml && grep recompute /etc/mdrj/node.yaml"

echo "==> Wipe DAG to start clean"
ssh "$TARGET" 'rm -f /var/lib/mdrj/node.db /var/lib/mdrj/node.db-shm /var/lib/mdrj/node.db-wal'

echo "==> Start mdrj"
ssh "$TARGET" 'systemctl start mdrj; sleep 8; systemctl is-active mdrj; systemctl status mdrj --no-pager 2>&1 | grep -E "Active:|Memory:|Tasks:" | head -5'

echo "==> Verify /status"
ssh "$TARGET" 'curl -s -m 10 http://localhost:9002/status' | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(f"  node_id={d[\"node_id\"]} state={d[\"state\"]}")
print(f"  size={d[\"consensus_membership_size\"]} hash={d[\"membership_snapshot_hash\"][:16]}")
print(f"  health={d[\"consensus_health\"]}")
'

echo
echo "==> Done. Germany joined cluster on low-memory profile."
echo "    Если опять упадёт — systemd прекратит restart loop через 3 попытки за 120с."
