#!/usr/bin/env bash
set -euo pipefail

echo "This helper prints suggested iptables commands to simulate a partition." >&2
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 group1,group2/..." >&2
  exit 1
fi

echo "For each group, drop outgoing traffic to the other groups. Example:" >&2
IFS='/' read -ra groups <<<"$1"
for group in "${groups[@]}"; do
  for other in "${groups[@]}"; do
    if [[ "$group" == "$other" ]]; then
      continue
    fi
    echo "  # Block from [$group] to [$other]" >&2
    IFS=',' read -ra srcs <<<"$group"
    IFS=',' read -ra dsts <<<"$other"
    for s in "${srcs[@]}"; do
      for d in "${dsts[@]}"; do
        echo "  iptables -A OUTPUT -p tcp --sport $((9000+${s})) --dport $((9000+${d})) -j DROP" >&2
      done
    done
  done
done

echo "Run scripts/demo_reconcile.sh to flush the example rules." >&2
