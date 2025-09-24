#!/usr/bin/env bash
set -euo pipefail

echo "Flush example iptables DROP rules used in partition demo" >&2
echo "sudo iptables -F" >&2
