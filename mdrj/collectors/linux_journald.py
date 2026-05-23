"""Linux journald collector: failed logins, sudo escalation, login bursts."""
from __future__ import annotations

import collections
import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, Iterable, List, Optional

from .base import BaseCollector, CollectedEvent

FAILED_SSH_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)


@dataclass
class JournaldCollectorConfig:
    enabled: bool = False
    units: List[str] = field(default_factory=lambda: ["ssh.service", "sshd.service"])
    burst_window_sec: int = 60
    burst_threshold: int = 10
    poll_interval_sec: float = 5.0


class LinuxJournaldCollector(BaseCollector):
    """Detect failed logins and login bursts by tailing journald."""

    name = "linux_journald"

    def __init__(
        self,
        *,
        config: JournaldCollectorConfig,
        node_id: str,
        host_id: Optional[str] = None,
        journalctl_path: Optional[str] = None,
    ) -> None:
        super().__init__(
            poll_interval_sec=config.poll_interval_sec,
            node_id=node_id,
            host_id=host_id or node_id,
        )
        self.config = config
        self._journalctl = journalctl_path or shutil.which("journalctl") or "/usr/bin/journalctl"
        self._failure_window: Deque[float] = collections.deque(maxlen=2048)
        self._last_cursor: Optional[str] = None
        self._last_burst_emit_at: float = 0.0
        if not shutil.which(self._journalctl):
            self.status.enabled = False
            self.status.last_error = "journalctl not available"

    def poll(self) -> List[CollectedEvent]:
        self.status.last_poll_at = time.time()
        if not self.status.enabled:
            return []
        try:
            raw_lines = self._fetch_journal()
        except FileNotFoundError as exc:
            self.status.last_error = str(exc)
            return []
        except Exception as exc:
            self.status.last_error = f"{type(exc).__name__}: {exc}"
            self.logger.exception("linux_journald poll failed")
            return []
        self.status.last_error = None
        events = list(self._parse_lines(raw_lines))
        for event in events:
            self.annotate(event)
        if events:
            self.status.last_event_at = time.time()
            self.status.emitted_count += len(events)
        return events

    # ------------------------------------------------------------------
    # Internals (kept small so tests can swap _fetch_journal via subclass)
    def _fetch_journal(self) -> Iterable[str]:
        args = [self._journalctl, "--output=json", "--no-pager", "-n", "200"]
        if self._last_cursor:
            args.extend(["--after-cursor", self._last_cursor])
        else:
            args.extend(["--since", f"-{int(self.poll_interval_sec * 3)}s"])
        for unit in self.config.units:
            args.extend(["-u", unit])
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise RuntimeError(f"journalctl exit {result.returncode}: {result.stderr.strip()[:200]}")
        return result.stdout.splitlines()

    def _parse_lines(self, lines: Iterable[str]) -> Iterable[CollectedEvent]:
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            cursor = record.get("__CURSOR")
            if cursor:
                self._last_cursor = cursor
            message = str(record.get("MESSAGE") or "")
            yield from self._extract_events_from_message(message, record)

    def _extract_events_from_message(
        self, message: str, record: Dict[str, object]
    ) -> Iterable[CollectedEvent]:
        match = FAILED_SSH_RE.search(message)
        if not match:
            return
        now = time.time()
        user = match.group("user")
        source_ip = match.group("ip")
        ts_realtime = _journal_realtime_ts(record)
        occurred_at = datetime.fromtimestamp(ts_realtime).isoformat(timespec="seconds")
        yield CollectedEvent(
            event_kind="admin_login_failure",
            payload={
                "principal": user,
                "source_ip": source_ip,
                "target_service": "sshd",
                "result": "failure",
                "occurred_at": occurred_at,
                "category": "authentication",
                "raw_line": message,
            },
        )
        self._failure_window.append(ts_realtime)
        burst_event = self._maybe_emit_burst(now, ts_realtime)
        if burst_event is not None:
            yield burst_event

    def _maybe_emit_burst(self, now: float, ts_realtime: float) -> Optional[CollectedEvent]:
        cutoff = ts_realtime - self.config.burst_window_sec
        while self._failure_window and self._failure_window[0] < cutoff:
            self._failure_window.popleft()
        if len(self._failure_window) < self.config.burst_threshold:
            return None
        # Дросселирование: один burst-event в окно, чтобы не флудить реестр.
        if now - self._last_burst_emit_at < self.config.burst_window_sec:
            return None
        self._last_burst_emit_at = now
        first_ts = self._failure_window[0]
        return CollectedEvent(
            event_kind="failed_login_burst",
            payload={
                "category": "authentication",
                "count": len(self._failure_window),
                "window_sec": self.config.burst_window_sec,
                "first_failure_at": datetime.fromtimestamp(first_ts).isoformat(timespec="seconds"),
                "last_failure_at": datetime.fromtimestamp(ts_realtime).isoformat(timespec="seconds"),
            },
        )


def _journal_realtime_ts(record: Dict[str, object]) -> float:
    raw = record.get("__REALTIME_TIMESTAMP")
    if raw is None:
        return time.time()
    try:
        return int(raw) / 1_000_000
    except (TypeError, ValueError):
        return time.time()
