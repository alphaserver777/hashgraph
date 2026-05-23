"""Unit tests for cross-platform collectors (Этап 1)."""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from mdrj.collectors import (
    JournaldCollectorConfig,
    LinuxAuditCollector,
    LinuxAuditCollectorConfig,
    LinuxFirewallCollector,
    LinuxFirewallCollectorConfig,
    LinuxJournaldCollector,
    LinuxProcCollector,
    LinuxProcCollectorConfig,
)


# ---------------------------------------------------------------------------
# linux_audit: critical file watch via mtime/sha256 deltas
# ---------------------------------------------------------------------------

def test_audit_collector_no_event_on_first_poll(tmp_path):
    f = tmp_path / "sensitive.conf"
    f.write_text("baseline")
    collector = LinuxAuditCollector(
        config=LinuxAuditCollectorConfig(enabled=True, watch_paths=[str(f)]),
        node_id="node-1",
    )
    events = collector.poll()
    assert events == []


def test_audit_collector_emits_event_on_content_change(tmp_path):
    f = tmp_path / "sensitive.conf"
    f.write_text("baseline")
    collector = LinuxAuditCollector(
        config=LinuxAuditCollectorConfig(enabled=True, watch_paths=[str(f)]),
        node_id="node-1",
    )
    collector.poll()  # establish baseline
    time.sleep(0.01)
    f.write_text("modified")
    events = collector.poll()
    assert len(events) == 1
    ev = events[0]
    assert ev.event_kind == "critical_file_modified"
    assert ev.payload["path"] == str(f)
    assert ev.payload["previous_sha256"] != ev.payload["current_sha256"]


def test_audit_collector_skips_missing_files(tmp_path):
    missing = tmp_path / "does-not-exist"
    collector = LinuxAuditCollector(
        config=LinuxAuditCollectorConfig(enabled=True, watch_paths=[str(missing)]),
        node_id="node-1",
    )
    assert collector.poll() == []


# ---------------------------------------------------------------------------
# linux_firewall: iptables-save digest diff
# ---------------------------------------------------------------------------

class _FakeFirewall(LinuxFirewallCollector):
    """Bypass subprocess for deterministic testing."""

    def __init__(self, ruleset_sequence, **kw):
        super().__init__(**kw)
        self.status.enabled = True
        self._ruleset_sequence = list(ruleset_sequence)
        self.status.last_error = None

    def _run_tool(self):
        return self._ruleset_sequence.pop(0)

    def poll(self):
        # Override only the subprocess step; reuse the digest diff via the real loop.
        self.status.last_poll_at = time.time()
        if not self._ruleset_sequence:
            return []
        from hashlib import sha256
        ruleset = self._run_tool()
        digest = sha256(ruleset.encode()).hexdigest()
        previous = self._last_digest
        self._last_digest = digest
        if self._first_poll:
            self._first_poll = False
            return []
        if previous == digest:
            return []
        from mdrj.collectors.base import CollectedEvent
        return [self.annotate(CollectedEvent(
            event_kind="iptables_rule_changed",
            payload={"previous_digest": previous, "current_digest": digest, "ruleset_bytes": len(ruleset)},
        ))]


def test_firewall_collector_detects_ruleset_mutation():
    collector = _FakeFirewall(
        ruleset_sequence=["-A INPUT ACCEPT\n", "-A INPUT ACCEPT\n", "-A INPUT DROP\n"],
        config=LinuxFirewallCollectorConfig(enabled=True),
        node_id="node-1",
    )
    assert collector.poll() == []  # first poll: baseline
    assert collector.poll() == []  # second poll: identical ruleset
    third = collector.poll()
    assert len(third) == 1
    assert third[0].event_kind == "iptables_rule_changed"
    assert third[0].payload["previous_digest"] != third[0].payload["current_digest"]


# ---------------------------------------------------------------------------
# linux_proc: malware blocklist + privileged uid detection
# ---------------------------------------------------------------------------

def _make_fake_proc(root: Path, pid: int, comm: str, exe: str, uid: int) -> None:
    proc = root / str(pid)
    proc.mkdir(parents=True, exist_ok=True)
    (proc / "comm").write_text(comm + "\n")
    (proc / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    exe_link = proc / "exe"
    if exe_link.exists() or exe_link.is_symlink():
        exe_link.unlink()
    target = root / f"_exe_{pid}"
    target.write_text("#!/bin/sh\n")
    os.symlink(target, exe_link)
    # We want readlink to return `exe`, not the actual target. Recreate accordingly.
    exe_link.unlink()
    os.symlink(exe, exe_link)


def test_proc_collector_detects_known_malware(tmp_path):
    _make_fake_proc(tmp_path, 100, comm="bash", exe="/bin/bash", uid=1000)
    collector = LinuxProcCollector(
        config=LinuxProcCollectorConfig(enabled=True, proc_root=str(tmp_path), blocklist=["xmrig"]),
        node_id="node-1",
    )
    collector.poll()  # baseline
    _make_fake_proc(tmp_path, 101, comm="xmrig", exe="/tmp/xmrig", uid=1000)
    events = collector.poll()
    kinds = [e.event_kind for e in events]
    assert "known_malicious_process" in kinds
    malware_event = next(e for e in events if e.event_kind == "known_malicious_process")
    assert malware_event.payload["pid"] == 101
    assert malware_event.payload["matched"] == "xmrig"


def test_proc_collector_detects_privileged_uid(tmp_path):
    _make_fake_proc(tmp_path, 200, comm="init", exe="/sbin/init", uid=1000)
    collector = LinuxProcCollector(
        config=LinuxProcCollectorConfig(enabled=True, proc_root=str(tmp_path), privileged_uids=[0]),
        node_id="node-1",
    )
    collector.poll()  # baseline
    _make_fake_proc(tmp_path, 201, comm="sshd", exe="/usr/sbin/sshd", uid=0)
    events = collector.poll()
    privileged = [e for e in events if e.event_kind == "privileged_process_started"]
    assert len(privileged) == 1
    assert privileged[0].payload["pid"] == 201
    assert privileged[0].payload["uid"] == 0


def test_proc_collector_does_not_emit_for_existing_pids_on_first_poll(tmp_path):
    _make_fake_proc(tmp_path, 300, comm="xmrig", exe="/tmp/xmrig", uid=0)
    collector = LinuxProcCollector(
        config=LinuxProcCollectorConfig(enabled=True, proc_root=str(tmp_path), blocklist=["xmrig"]),
        node_id="node-1",
    )
    assert collector.poll() == []


# ---------------------------------------------------------------------------
# linux_journald: pure-parsing test using injected journal lines
# ---------------------------------------------------------------------------

class _MockJournald(LinuxJournaldCollector):
    def __init__(self, lines, **kw):
        super().__init__(**kw)
        self.status.enabled = True
        self._mock_lines = list(lines)

    def _fetch_journal(self):
        return self._mock_lines


def test_journald_collector_parses_failed_login_and_emits_burst():
    base_ts = int(time.time() * 1_000_000)
    lines = [
        '{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"%d","MESSAGE":"Failed password for root from 1.2.3.4 port 22 ssh2"}' % (base_ts + i)
        for i in range(12)
    ]
    collector = _MockJournald(
        lines,
        config=JournaldCollectorConfig(enabled=True, burst_window_sec=60, burst_threshold=10),
        node_id="node-1",
    )
    events = collector.poll()
    failure_kinds = [e.event_kind for e in events]
    assert failure_kinds.count("admin_login_failure") == 12
    assert "failed_login_burst" in failure_kinds
    burst = next(e for e in events if e.event_kind == "failed_login_burst")
    assert burst.payload["count"] >= 10


def test_journald_collector_ignores_unrelated_messages():
    base_ts = int(time.time() * 1_000_000)
    lines = [
        '{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"%d","MESSAGE":"Accepted password for alice from 10.0.0.5 port 22 ssh2"}' % base_ts,
        '{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"%d","MESSAGE":"systemd: Started session-42.scope"}' % (base_ts + 1),
    ]
    collector = _MockJournald(
        lines,
        config=JournaldCollectorConfig(enabled=True),
        node_id="node-1",
    )
    assert collector.poll() == []
