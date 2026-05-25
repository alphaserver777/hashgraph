#!/usr/bin/env bash
# Chaos script: kills a random MDRJ pod every INTERVAL seconds.
#
# Demonstrates that the cluster survives ⌊(N-1)/3⌋ simultaneous failures
# (for N=5, up to 1 sustained loss without breaking checkpoint quorum).
#
# Usage:
#   scripts/k3s/chaos.sh [--interval 30] [--namespace mdrj] [--label app=mdrj-dag] [--rounds 10]
set -euo pipefail

INTERVAL=30
NAMESPACE=mdrj
LABEL="app=mdrj-dag"
ROUNDS=10

while [[ $# -gt 0 ]]; do
  case $1 in
    --interval) INTERVAL=$2; shift 2;;
    --namespace) NAMESPACE=$2; shift 2;;
    --label) LABEL=$2; shift 2;;
    --rounds) ROUNDS=$2; shift 2;;
    *) echo "unknown: $1"; exit 2;;
  esac
done

echo "chaos: kill one random pod every ${INTERVAL}s, ${ROUNDS} rounds total"
echo "       namespace=${NAMESPACE} label=${LABEL}"
echo ""

for ((i=1; i<=ROUNDS; i++)); do
  pods=$(kubectl -n "$NAMESPACE" get pods -l "$LABEL" -o jsonpath='{.items[*].metadata.name}')
  if [[ -z "$pods" ]]; then
    echo "[$i/$ROUNDS] no pods found — exiting"
    exit 1
  fi
  read -ra arr <<< "$pods"
  victim=${arr[$((RANDOM % ${#arr[@]}))]}
  ts=$(date +%H:%M:%S)
  echo "[$ts][$i/$ROUNDS] killing pod: $victim"
  kubectl -n "$NAMESPACE" delete pod "$victim" --grace-period=0 --force >/dev/null 2>&1 || true
  # Cluster status snapshot
  ready=$(kubectl -n "$NAMESPACE" get pods -l "$LABEL" -o jsonpath='{range .items[*]}{.metadata.name}={.status.containerStatuses[0].ready}{"\n"}{end}' | grep -c =true || true)
  total=$(echo "$pods" | wc -w)
  echo "         ready ${ready}/${total} pods"
  sleep "$INTERVAL"
done

echo ""
echo "chaos: done"
