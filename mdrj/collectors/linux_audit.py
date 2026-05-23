"""Linux critical-file integrity collector.

Polls a configured list of critical files (passwd, shadow, sshd_config,
sudoers, etc.) and emits `critical_file_modified` when mtime or content
hash changes between polls. This is a deliberately minimal stand-in for a
full auditd integration — it does not need the audit daemon, runs on any
Linux/macOS, and is sufficient as the first vertical slice of file
integrity monitoring.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .base import BaseCollector, CollectedEvent

DEFAULT_WATCH_PATHS = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/pam.d/sshd",
)


@dataclass
class FileWatchSnapshot:
    mtime_ns: int
    size: int
    sha256: str


@dataclass
class LinuxAuditCollectorConfig:
    enabled: bool = False
    watch_paths: List[str] = field(default_factory=lambda: list(DEFAULT_WATCH_PATHS))
    poll_interval_sec: float = 5.0
    hash_max_bytes: int = 1_048_576  # files larger than this skip content hashing


class LinuxAuditCollector(BaseCollector):
    """Watch critical config files for modification."""

    name = "linux_audit"

    def __init__(
        self,
        *,
        config: LinuxAuditCollectorConfig,
        node_id: str,
        host_id: Optional[str] = None,
    ) -> None:
        super().__init__(
            poll_interval_sec=config.poll_interval_sec,
            node_id=node_id,
            host_id=host_id or node_id,
        )
        self.config = config
        self._snapshots: Dict[str, FileWatchSnapshot] = {}
        self._first_poll = True

    def poll(self) -> List[CollectedEvent]:
        self.status.last_poll_at = time.time()
        if not self.status.enabled:
            return []
        events: List[CollectedEvent] = []
        for raw_path in self.config.watch_paths:
            path = Path(raw_path)
            snapshot = self._snapshot(path)
            if snapshot is None:
                self._snapshots.pop(str(path), None)
                continue
            previous = self._snapshots.get(str(path))
            self._snapshots[str(path)] = snapshot
            if self._first_poll or previous is None:
                continue
            if previous.sha256 != snapshot.sha256 or previous.mtime_ns != snapshot.mtime_ns:
                events.append(
                    self.annotate(
                        CollectedEvent(
                            event_kind="critical_file_modified",
                            payload={
                                "category": "integrity",
                                "path": str(path),
                                "previous_sha256": previous.sha256,
                                "current_sha256": snapshot.sha256,
                                "size_bytes": snapshot.size,
                                "mtime_iso": datetime.fromtimestamp(snapshot.mtime_ns / 1e9).isoformat(timespec="seconds"),
                            },
                        )
                    )
                )
        self._first_poll = False
        self.status.last_error = None
        if events:
            self.status.last_event_at = time.time()
            self.status.emitted_count += len(events)
        return events

    def _snapshot(self, path: Path) -> Optional[FileWatchSnapshot]:
        try:
            stat = path.stat()
        except FileNotFoundError:
            return None
        except PermissionError as exc:
            self.status.last_error = f"permission denied: {path}"
            self.logger.debug("permission denied reading %s: %s", path, exc)
            return None
        sha256 = ""
        if stat.st_size <= self.config.hash_max_bytes:
            try:
                sha256 = _hash_file(path)
            except (OSError, PermissionError) as exc:
                self.logger.debug("hash failed for %s: %s", path, exc)
        return FileWatchSnapshot(
            mtime_ns=getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1e9)),
            size=int(stat.st_size),
            sha256=sha256,
        )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()
