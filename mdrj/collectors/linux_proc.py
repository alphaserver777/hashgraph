"""Linux process snapshot collector.

Periodically enumerates /proc to detect:
- Newly launched processes whose executable basename is on a malware
  blocklist → `known_malicious_process`.
- Newly launched processes running with EUID=0 (or matching configured
  privileged uids) → `privileged_process_started`.

Stateful: keeps a set of seen PIDs across polls so existing processes
do not re-emit on every interval.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Set

from .base import BaseCollector, CollectedEvent

DEFAULT_MALWARE_BLOCKLIST = (
    "xmrig",
    "minerd",
    "kdevtmpfsi",
    "kinsing",
    "tsunami",
)


@dataclass
class LinuxProcCollectorConfig:
    enabled: bool = False
    blocklist: List[str] = field(default_factory=lambda: list(DEFAULT_MALWARE_BLOCKLIST))
    privileged_uids: List[int] = field(default_factory=lambda: [0])
    poll_interval_sec: float = 3.0
    proc_root: str = "/proc"


class LinuxProcCollector(BaseCollector):
    name = "linux_proc"

    def __init__(
        self,
        *,
        config: LinuxProcCollectorConfig,
        node_id: str,
        host_id: Optional[str] = None,
    ) -> None:
        super().__init__(
            poll_interval_sec=config.poll_interval_sec,
            node_id=node_id,
            host_id=host_id or node_id,
        )
        self.config = config
        self._seen_pids: Set[int] = set()
        self._first_poll = True
        self._blocklist_lower = {name.lower() for name in config.blocklist if name}
        self._privileged_uids = set(int(uid) for uid in config.privileged_uids)
        if not Path(config.proc_root).is_dir():
            self.status.enabled = False
            self.status.last_error = f"{config.proc_root} not a directory"

    def poll(self) -> List[CollectedEvent]:
        self.status.last_poll_at = time.time()
        if not self.status.enabled:
            return []
        events: List[CollectedEvent] = []
        current_pids: Set[int] = set()
        for pid in self._iter_pids():
            current_pids.add(pid)
            if pid in self._seen_pids:
                continue
            info = self._read_proc(pid)
            if info is None:
                continue
            if self._first_poll:
                continue
            exe_basename = (info.get("exe") or "").rsplit("/", 1)[-1].lower()
            comm = (info.get("comm") or "").lower()
            uid = info.get("uid")
            if exe_basename and exe_basename in self._blocklist_lower or comm in self._blocklist_lower:
                events.append(
                    self.annotate(
                        CollectedEvent(
                            event_kind="known_malicious_process",
                            payload={
                                "category": "malware",
                                "pid": pid,
                                "exe": info.get("exe"),
                                "comm": info.get("comm"),
                                "uid": uid,
                                "matched": exe_basename if exe_basename in self._blocklist_lower else comm,
                            },
                        )
                    )
                )
                continue
            if uid is not None and int(uid) in self._privileged_uids:
                events.append(
                    self.annotate(
                        CollectedEvent(
                            event_kind="privileged_process_started",
                            payload={
                                "category": "process",
                                "pid": pid,
                                "exe": info.get("exe"),
                                "comm": info.get("comm"),
                                "uid": uid,
                            },
                        )
                    )
                )
        self._seen_pids = current_pids
        self._first_poll = False
        self.status.last_error = None
        if events:
            self.status.last_event_at = time.time()
            self.status.emitted_count += len(events)
        return events

    def _iter_pids(self) -> Iterable[int]:
        root = Path(self.config.proc_root)
        try:
            for entry in root.iterdir():
                if entry.name.isdigit():
                    yield int(entry.name)
        except OSError as exc:
            self.status.last_error = str(exc)
            return

    def _read_proc(self, pid: int) -> Optional[dict]:
        base = Path(self.config.proc_root) / str(pid)
        try:
            comm = (base / "comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
        try:
            exe = os.readlink(base / "exe")
        except OSError:
            exe = ""
        uid: Optional[int] = None
        try:
            status_text = (base / "status").read_text(encoding="utf-8", errors="replace")
            for line in status_text.splitlines():
                if line.startswith("Uid:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        uid = int(parts[1])
                    break
        except OSError:
            return None
        return {"comm": comm, "exe": exe, "uid": uid}
