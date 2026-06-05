#!/usr/bin/env bash
# Deploy MDRJ-DAG distributed cluster (A4) on N servers via ssh.
#
# Each server runs ONE systemd service: mdrj.service (peer-to-peer mode).
# All servers see each other through the peers list resolved from their
# public IPv4 addresses.
#
# Layout per server:
#   /opt/mdrj            git clone of the repository
#   /opt/mdrj/.venv      python virtual environment with mdrj installed
#   /etc/mdrj/node.yaml  configuration
#   /var/lib/mdrj/       SQLite database
#   systemd: mdrj.service
#
# Usage:
#   scripts/experiment/install.sh \
#     --peers France,Germany,Germany2,Zomro \
#     --hmac-key "$(openssl rand -hex 32)"
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/alphaserver777/hashgraph.git}"
BRANCH="${BRANCH:-main}"
PEERS=""
HMAC_KEY=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --peers) PEERS=$2; shift 2;;
    --hmac-key) HMAC_KEY=$2; shift 2;;
    --branch) BRANCH=$2; shift 2;;
    --repo) REPO_URL=$2; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done

if [[ -z "$PEERS" || -z "$HMAC_KEY" ]]; then
  echo "Usage: $0 --peers ssh1,ssh2,ssh3,ssh4 --hmac-key <hex32>"
  exit 2
fi

IFS=',' read -ra PEER_LIST <<< "$PEERS"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "============================================"
echo "MDRJ-DAG distributed cluster install (A4)"
echo "  Peers:  ${PEER_LIST[*]}"
echo "  Repo:   $REPO_URL @ $BRANCH"
echo "============================================"
echo ""

# Resolve every peer's public IP for the peers list.
declare -A PEER_IP
for host in "${PEER_LIST[@]}"; do
  echo "[..] Resolving IP of $host ..."
  ip=$(ssh -o ConnectTimeout=10 "$host" \
    'ip -4 addr show scope global | grep -oE "inet [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" | head -1 | awk "{print \$2}"' 2>/dev/null || echo "")
  if [[ -z "$ip" ]]; then
    echo "  WARNING: cannot reach $host — skipping"
    continue
  fi
  PEER_IP[$host]=$ip
  echo "  $host = $ip"
done

# Build peers block (YAML list of host:port for all OTHER peers).
build_peers_block() {
  local self_host=$1
  local block=""
  for h in "${!PEER_IP[@]}"; do
    if [[ "$h" == "$self_host" ]]; then continue; fi
    block+="  - ${PEER_IP[$h]}:9002"$'\n'
  done
  printf '%s' "$block"
}

install_one() {
  local host=$1
  local self_ip="${PEER_IP[$host]:-}"
  if [[ -z "$self_ip" ]]; then
    echo "  $host: no IP — skip"
    return 0
  fi
  local peers_block
  peers_block=$(build_peers_block "$host")

  echo ""
  echo "==== Installing on $host (ip=$self_ip) ===="

  local node_yaml
  node_yaml=$(sed -e "s/__NODE_ID__/${host}/g" -e "s|__HMAC_KEY__|$HMAC_KEY|g" \
                "$REPO_ROOT/deploy/experiment/node.yaml.tpl")
  node_yaml=$(python3 -c "
import sys
text = sys.stdin.read()
block = '''$peers_block'''
print(text.replace('__PEERS_BLOCK__', block.rstrip('\\n')))
" <<< "$node_yaml")

  ssh "$host" "bash -s" <<EOF
set -euo pipefail

# 1. System dependencies
PY_VER=\$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "")
if [[ -n "\$PY_VER" ]]; then
  apt-get install -y -qq "python\${PY_VER}-venv" 2>/dev/null || apt-get install -y -qq python3-venv
else
  apt-get update -qq && apt-get install -y -qq python3 python3-venv python3-pip git
fi
if ! command -v git >/dev/null; then
  apt-get install -y -qq git
fi

# 2. Clone or update repo (force-reset to drop any local junk from .venv/__pycache__)
if [[ ! -d /opt/mdrj/.git ]]; then
  rm -rf /opt/mdrj
  git clone -b "$BRANCH" "$REPO_URL" /opt/mdrj
else
  cd /opt/mdrj && git fetch origin --quiet && git checkout "$BRANCH" 2>/dev/null \
    && git reset --hard "origin/$BRANCH" --quiet
fi

# 3. Python virtual environment (always recreate to avoid stale shebangs)
cd /opt/mdrj
rm -rf .venv
python3 -m venv .venv
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -e . -q

# 4. State directories
mkdir -p /etc/mdrj /var/lib/mdrj /var/log/mdrj
chmod 750 /etc/mdrj /var/lib/mdrj /var/log/mdrj

# 5. Write config
cat > /etc/mdrj/node.yaml <<'NODE_YAML'
$node_yaml
NODE_YAML

# 6. Install systemd unit
cp /opt/mdrj/deploy/systemd/mdrj.service /etc/systemd/system/
systemctl daemon-reload

# 7. Firewall (port 9002 for peer-to-peer gossip and UI)
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow 9002/tcp || true
fi

# 8. Enable and start
systemctl enable mdrj.service >/dev/null 2>&1
systemctl restart mdrj.service

# 9. Health check с ретраями: aiohttp слушает не сразу
echo "--- mdrj status ---"
for i in 1 2 3 4 5 6 7 8 9 10; do
  if systemctl is-active mdrj >/dev/null && curl -fsS -m 3 http://localhost:9002/status >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
systemctl is-active mdrj || (journalctl -u mdrj -n 20 --no-pager; exit 1)
curl -fsS http://localhost:9002/status | python3 -c "import json,sys; d=json.load(sys.stdin); print('  node_id=', d['node_id'], 'state=', d['state'], 'peers=', len([p for p in d['peers'] if not p['is_self']]))"
echo "  $host: OK"
EOF
}

for host in "${PEER_LIST[@]}"; do
  install_one "$host"
done

echo ""
echo "============================================"
echo "Install complete."
echo "Peer URLs:"
for h in "${!PEER_IP[@]}"; do
  echo "  $h  → http://${PEER_IP[$h]}:9002/viz   (graph)"
  echo "         http://${PEER_IP[$h]}:9002/metrics/dashboard"
done
echo "============================================"
