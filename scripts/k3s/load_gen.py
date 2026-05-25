#!/usr/bin/env python3
"""Load generator for MDRJ-DAG k3s demo.

Picks a random pod each round and emits N events/sec across a configurable
mix of event_kinds. Used to drive the cluster during chaos demonstrations
and to populate /metrics/dashboard with realistic data points.

Usage:
    python scripts/k3s/load_gen.py \\
        --pods mdrj-0:30901,mdrj-1:30901,mdrj-2:30901,mdrj-3:30901,mdrj-4:30901 \\
        --rate 10 \\
        --duration 300 \\
        --hmac-key "$(kubectl -n mdrj get secret mdrj-secrets -o jsonpath='{.data.hmac-key}' | base64 -d)"

If addresses are pod hostnames, also pass --through-ingress with the LB
host:port. By default the script uses the NodePort 30901 on the host that
runs k3s.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac as _hmac
import json
import random
import sys
import time
import urllib.request

EVENT_KINDS = [
    ("admin_login_failure", 0.30),
    ("failed_login_burst", 0.05),
    ("critical_file_modified", 0.10),
    ("known_malicious_process", 0.05),
    ("privileged_process_started", 0.20),
    ("firewall_rule_changed", 0.05),
    ("admin_ssh_login_success", 0.10),
    ("heartbeat", 0.15),
]


def weighted_choice(weighted):
    r = random.random()
    acc = 0.0
    for value, weight in weighted:
        acc += weight
        if r <= acc:
            return value
    return weighted[-1][0]


def sign_body(key: str, body: bytes) -> str:
    return _hmac.new(key.encode(), body, hashlib.sha256).hexdigest()


def emit_one(pod: str, hmac_key: str | None) -> tuple[bool, float, int]:
    event_kind = weighted_choice(EVENT_KINDS)
    payload = {
        "event_kind": event_kind,
        "host_id": f"host-{random.randint(1, 50)}",
        "source_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "principal": f"user{random.randint(1,200)}",
        "ts": time.time(),
    }
    body = json.dumps({"event_kind": event_kind, "payload": payload}).encode()
    headers = {"Content-Type": "application/json"}
    if hmac_key:
        headers["X-MDRJ-Sig"] = sign_body(hmac_key, body)
    url = f"http://{pod}/event/emit"
    start = time.perf_counter()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            _ = resp.read()
            return True, time.perf_counter() - start, resp.status
    except Exception as exc:
        return False, time.perf_counter() - start, -1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pods", required=True,
                        help="Comma-separated list of host:port (e.g. NodePort 30901)")
    parser.add_argument("--rate", type=int, default=10, help="Events per second")
    parser.add_argument("--duration", type=int, default=60, help="Seconds to run")
    parser.add_argument("--hmac-key", default=None, help="Cluster HMAC key (if set)")
    parser.add_argument("--print-every", type=int, default=50, help="Status print interval (events)")
    args = parser.parse_args()

    pods = [p.strip() for p in args.pods.split(",") if p.strip()]
    if not pods:
        print("no pods", file=sys.stderr)
        sys.exit(2)

    interval = 1.0 / max(1, args.rate)
    end_at = time.time() + args.duration
    total = ok = fail = 0
    sum_latency = 0.0
    status_counts: dict[int, int] = {}
    start = time.time()
    print(f"load_gen: rate={args.rate} eps duration={args.duration}s pods={len(pods)}")
    try:
        while time.time() < end_at:
            pod = random.choice(pods)
            success, latency, status = emit_one(pod, args.hmac_key)
            total += 1
            sum_latency += latency
            status_counts[status] = status_counts.get(status, 0) + 1
            if success:
                ok += 1
            else:
                fail += 1
            if total % args.print_every == 0:
                rate_actual = total / max(0.1, time.time() - start)
                avg_ms = (sum_latency / total) * 1000
                print(f"  total={total:6d} ok={ok:6d} fail={fail:5d} "
                      f"rate_actual={rate_actual:5.1f} eps avg_lat={avg_ms:5.1f} ms "
                      f"status_dist={status_counts}")
            time.sleep(max(0, interval))
    except KeyboardInterrupt:
        print("\ninterrupted")
    elapsed = time.time() - start
    rate_actual = total / max(0.1, elapsed)
    print(f"DONE: total={total} ok={ok} fail={fail} "
          f"elapsed={elapsed:.1f}s avg_rate={rate_actual:.1f} eps "
          f"avg_lat_ms={(sum_latency/max(1,total))*1000:.2f}")


if __name__ == "__main__":
    main()
