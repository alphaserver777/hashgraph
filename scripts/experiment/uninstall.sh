#!/usr/bin/env bash
# Cleanly remove the MDRJ-DAG cluster from all servers.
# Removes both legacy scenario1/scenario2 services (for compat) and the
# unified mdrj.service introduced after the A1 baseline was dropped.
set -euo pipefail

PEERS=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --peers) PEERS=$2; shift 2;;
    *) echo "unknown: $1"; exit 2;;
  esac
done

if [[ -z "$PEERS" ]]; then
  echo "Usage: $0 --peers ssh1,ssh2,ssh3,ssh4"
  exit 2
fi

IFS=',' read -ra PEER_LIST <<< "$PEERS"
for host in "${PEER_LIST[@]}"; do
  echo "=== removing on $host ==="
  ssh "$host" "bash -s" <<'EOF'
systemctl stop mdrj mdrj-scenario1 mdrj-scenario2 2>/dev/null || true
systemctl disable mdrj mdrj-scenario1 mdrj-scenario2 2>/dev/null || true
rm -f /etc/systemd/system/mdrj.service \
      /etc/systemd/system/mdrj-scenario1.service \
      /etc/systemd/system/mdrj-scenario2.service
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true
rm -rf /opt/mdrj /etc/mdrj /var/lib/mdrj /var/log/mdrj
echo "  cleaned"
EOF
done
echo "All hosts cleaned."
