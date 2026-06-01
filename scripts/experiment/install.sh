#!/usr/bin/env bash
# Deploy MDRJ-DAG experiment stand on N servers via ssh.
#
# Layout per server:
#   /opt/mdrj            git clone of the repository
#   /opt/mdrj/.venv      python virtual environment with mdrj installed
#   /etc/mdrj/           configs for both scenarios
#   /var/lib/mdrj/       SQLite databases
#   systemd: mdrj-scenario1.service + mdrj-scenario2.service
#
# Usage:
#   scripts/experiment/install.sh \
#     --central Germany \
#     --peers France,Germany,Germany2,Zomro \
#     --hmac-key "$(openssl rand -hex 32)" \
#     --branch protocol/hashgraph-consensus-alignment
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/alphaserver777/hashgraph.git}"
BRANCH="${BRANCH:-protocol/hashgraph-consensus-alignment}"
CENTRAL=""
PEERS=""
HMAC_KEY=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --central) CENTRAL=$2; shift 2;;
    --peers) PEERS=$2; shift 2;;
    --hmac-key) HMAC_KEY=$2; shift 2;;
    --branch) BRANCH=$2; shift 2;;
    --repo) REPO_URL=$2; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done

if [[ -z "$CENTRAL" || -z "$PEERS" || -z "$HMAC_KEY" ]]; then
  echo "Usage: $0 --central <ssh_alias> --peers <a,b,c,d> --hmac-key <hex32>"
  exit 2
fi

IFS=',' read -ra PEER_LIST <<< "$PEERS"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "============================================"
echo "MDRJ-DAG experiment install"
echo "  Central (Scenario 1): $CENTRAL"
echo "  Peers (Scenario 2):   ${PEER_LIST[*]}"
echo "  Repo:                 $REPO_URL @ $BRANCH"
echo "============================================"
echo ""

# Resolve external IP for the central server (peers point at it for Scenario 1).
echo "[1/N] Resolving public IP of central host $CENTRAL ..."
CENTRAL_IP=$(ssh -o ConnectTimeout=10 "$CENTRAL" \
  'ip -4 addr show scope global | grep -oE "inet [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" | head -1 | awk "{print \$2}"')
if [[ -z "$CENTRAL_IP" ]]; then
  echo "  could not resolve central IP, aborting"
  exit 3
fi
echo "  central IP = $CENTRAL_IP"
CENTRAL_URL="http://${CENTRAL_IP}:9001"

# Resolve every peer's public IP for Scenario 2 peer list.
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

# Build scenario2 peers block (YAML list of host:port for all OTHER peers).
build_peers_block() {
  local self_host=$1
  local block=""
  for h in "${!PEER_IP[@]}"; do
    if [[ "$h" == "$self_host" ]]; then continue; fi
    block+="  - ${PEER_IP[$h]}:9002"$'\n'
  done
  # Trim trailing newline
  printf '%s' "$block"
}

install_one() {
  local host=$1
  local role=$2  # central | agent
  local self_ip="${PEER_IP[$host]:-}"
  if [[ -z "$self_ip" ]]; then
    echo "  $host: no IP — skip"
    return 0
  fi
  local peers_block
  peers_block=$(build_peers_block "$host")

  echo ""
  echo "==== Installing on $host (role=$role, ip=$self_ip) ===="

  # Build the scenario1 yaml content (central vs agent).
  local s1_yaml
  if [[ "$role" == "central" ]]; then
    s1_yaml=$(sed -e "s/__NODE_ID__/${host}-s1/g" -e "s|__HMAC_KEY__|$HMAC_KEY|g" \
               "$REPO_ROOT/deploy/experiment/scenario1.central.yaml.tpl")
  else
    s1_yaml=$(sed -e "s/__NODE_ID__/${host}-s1/g" -e "s|__HMAC_KEY__|$HMAC_KEY|g" \
                  -e "s|__CENTRAL_URL__|$CENTRAL_URL|g" \
               "$REPO_ROOT/deploy/experiment/scenario1.agent.yaml.tpl")
  fi
  # Scenario 2 yaml — every host is a peer.
  local s2_yaml
  s2_yaml=$(sed -e "s/__NODE_ID__/${host}-s2/g" -e "s|__HMAC_KEY__|$HMAC_KEY|g" \
              "$REPO_ROOT/deploy/experiment/scenario2.peer.yaml.tpl")
  # Replace peers block (sed multiline trick): use python over ssh
  s2_yaml=$(python3 -c "
import sys
text = sys.stdin.read()
block = '''$peers_block'''
print(text.replace('__PEERS_BLOCK__', block.rstrip('\\n')))
" <<< "$s2_yaml")

  # Push everything in one ssh session
  ssh "$host" "bash -s" <<EOF
set -euo pipefail

# 1. Install dependencies
if ! command -v python3 >/dev/null; then
  apt-get update -qq && apt-get install -y -qq python3 python3-venv python3-pip git
fi
if ! command -v git >/dev/null; then
  apt-get install -y -qq git
fi

# 2. Clone or update repo
if [[ ! -d /opt/mdrj/.git ]]; then
  rm -rf /opt/mdrj
  git clone -b "$BRANCH" "$REPO_URL" /opt/mdrj
else
  cd /opt/mdrj && git fetch --all && git checkout "$BRANCH" && git pull --ff-only
fi

# 3. Python virtual environment
cd /opt/mdrj
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -e . -q

# 4. Make state directories
mkdir -p /etc/mdrj /var/lib/mdrj /var/log/mdrj
chmod 750 /etc/mdrj /var/lib/mdrj /var/log/mdrj

# 5. Write configs
cat > /etc/mdrj/scenario1.yaml <<'YAML_S1'
$s1_yaml
YAML_S1
cat > /etc/mdrj/scenario2.yaml <<'YAML_S2'
$s2_yaml
YAML_S2

# 6. Install systemd units
cp /opt/mdrj/deploy/systemd/mdrj-scenario1.service /etc/systemd/system/
cp /opt/mdrj/deploy/systemd/mdrj-scenario2.service /etc/systemd/system/
systemctl daemon-reload

# 7. Open firewall for 9001/9002 if ufw is present
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow 9001/tcp || true
  ufw allow 9002/tcp || true
fi

# 8. Enable and start services
systemctl enable mdrj-scenario1.service mdrj-scenario2.service >/dev/null 2>&1
systemctl restart mdrj-scenario1.service
systemctl restart mdrj-scenario2.service

# 9. Brief health check
sleep 3
echo "--- mdrj-scenario1 status ---"
systemctl is-active mdrj-scenario1 || (journalctl -u mdrj-scenario1 -n 20 --no-pager; exit 1)
echo "--- mdrj-scenario2 status ---"
systemctl is-active mdrj-scenario2 || (journalctl -u mdrj-scenario2 -n 20 --no-pager; exit 1)
curl -fsS http://localhost:9001/status | python3 -c "import json,sys; d=json.load(sys.stdin); print('  s1: node_id=', d['node_id'], 'state=', d['state'])"
curl -fsS http://localhost:9002/status | python3 -c "import json,sys; d=json.load(sys.stdin); print('  s2: node_id=', d['node_id'], 'state=', d['state'])"
echo "  $host: OK"
EOF
}

# Install on central first, then on all agents/peers.
install_one "$CENTRAL" "central"
for host in "${PEER_LIST[@]}"; do
  if [[ "$host" == "$CENTRAL" ]]; then continue; fi
  install_one "$host" "agent"
done

echo ""
echo "============================================"
echo "Install complete."
echo "  Central (S1) HTTP: $CENTRAL_URL"
echo "  Peer HTTP ports:   $(for h in "${!PEER_IP[@]}"; do printf '%s=9002 ' "$h"; done)"
echo ""
echo "Quick checks:"
echo "  ssh $CENTRAL 'curl -fsS http://localhost:9001/peers | python3 -m json.tool'"
echo "  ssh ${PEER_LIST[0]} 'curl -fsS http://localhost:9002/peers | python3 -m json.tool'"
echo "============================================"
