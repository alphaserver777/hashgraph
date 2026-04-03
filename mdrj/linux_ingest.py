"""Minimal Linux ingestion helpers for self-contained node containers."""
from __future__ import annotations

import grp
import json
import pwd
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .config import LinuxIngestConfig


SSH_ACCEPTED_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd(?:\[\d+\])?:\s+"
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>[\w.@-]+)\s+from\s+"
    r"(?P<source_ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)"
)


@dataclass(slots=True)
class LinuxIngestStatus:
    enabled: bool
    source_type: str
    source_path: Optional[str]
    host_id: Optional[str]
    last_poll_at: Optional[float] = None
    last_event_at: Optional[float] = None
    last_error: Optional[str] = None
    emitted_count: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "enabled": self.enabled,
            "source_type": self.source_type,
            "source_path": self.source_path,
            "host_id": self.host_id,
            "last_poll_at": self.last_poll_at,
            "last_event_at": self.last_event_at,
            "last_error": self.last_error,
            "emitted_count": self.emitted_count,
        }


class LinuxAuthLogIngestor:
    """Tail a Linux auth log and extract successful administrative SSH logins."""

    def __init__(
        self,
        *,
        config: LinuxIngestConfig,
        node_id: str,
        default_state_path: Optional[str] = None,
    ) -> None:
        self.config = config
        self.node_id = node_id
        self.auth_log_path = Path(config.auth_log_path or "")
        state_path = config.state_path or default_state_path
        self.state_path = Path(state_path) if state_path else None
        self.host_id = config.host_id or node_id
        self._state = self._load_state()
        self._admin_users = {user.strip() for user in config.admin_users if str(user).strip()}
        self._privileged_groups = {
            group.strip() for group in config.privileged_groups if str(group).strip()
        }

    def poll(self) -> List[Dict[str, object]]:
        now = time.time()
        if not self.auth_log_path.exists():
            raise FileNotFoundError(f"auth log path does not exist: {self.auth_log_path}")

        stat = self.auth_log_path.stat()
        state_inode = int(self._state.get("inode", 0) or 0)
        state_offset = int(self._state.get("offset", 0) or 0)
        offset = state_offset
        if state_inode != stat.st_ino or stat.st_size < offset:
            offset = 0

        events: List[Dict[str, object]] = []
        with self.auth_log_path.open("r", encoding="utf-8", errors="replace") as fp:
            fp.seek(offset)
            while True:
                line_offset = fp.tell()
                line = fp.readline()
                if not line:
                    break
                payload = self._parse_line(line.rstrip("\n"), line_offset, now)
                if payload is not None:
                    events.append(payload)
            offset = fp.tell()

        self._state = {"inode": stat.st_ino, "offset": offset}
        self._save_state()
        return events

    def _parse_line(
        self,
        line: str,
        line_offset: int,
        collected_at_ts: float,
    ) -> Optional[Dict[str, object]]:
        match = SSH_ACCEPTED_RE.match(line)
        if not match:
            return None

        principal = match.group("user")
        privilege_scope = self._privilege_scope(principal)
        if privilege_scope is None:
            return None

        occurred_at = self._parse_timestamp(
            month=match.group("month"),
            day=match.group("day"),
            clock=match.group("clock"),
        )
        source_ip = match.group("source_ip")
        method = match.group("method")
        ssh_port = int(match.group("port"))
        collected_at = datetime.utcfromtimestamp(collected_at_ts).isoformat(timespec="seconds") + "Z"
        title = f"Успешный административный SSH-вход: {principal}"
        description = (
            f"Подтверждён вход по SSH под административной учётной записью {principal} "
            f"с адреса {source_ip}."
        )
        raw_ref = f"{self.auth_log_path}:{line_offset}"
        return {
            "event_kind": "admin_ssh_login_success",
            "class": "A",
            "host_id": self.host_id,
            "node_id": self.node_id,
            "occurred_at": occurred_at,
            "collected_at": collected_at,
            "principal": principal,
            "source_ip": source_ip,
            "target_service": "sshd",
            "result": "success",
            "privilege_scope": privilege_scope,
            "raw_ref": raw_ref,
            "title": title,
            "description": description,
            "category": "authentication",
            "context": {
                "source_type": self.config.source_type,
                "ssh_auth_method": method,
                "ssh_port": ssh_port,
                "raw_line": line,
            },
        }

    def _privilege_scope(self, principal: str) -> Optional[str]:
        if principal == "root":
            return "root"
        if principal in self._admin_users:
            return "configured_admin_user"
        if self._privileged_groups and self._principal_in_privileged_group(principal):
            return "privileged_group"
        return None

    def _principal_in_privileged_group(self, principal: str) -> bool:
        try:
            user_info = pwd.getpwnam(principal)
        except KeyError:
            return False
        for group_name in self._privileged_groups:
            try:
                group_info = grp.getgrnam(group_name)
            except KeyError:
                continue
            if principal in group_info.gr_mem or group_info.gr_gid == user_info.pw_gid:
                return True
        return False

    def _parse_timestamp(self, *, month: str, day: str, clock: str) -> str:
        now = datetime.now()
        candidate = datetime.strptime(
            f"{now.year} {month} {day} {clock}",
            "%Y %b %d %H:%M:%S",
        )
        if candidate.timestamp() - now.timestamp() > 86400:
            candidate = candidate.replace(year=now.year - 1)
        return candidate.isoformat(timespec="seconds")

    def _load_state(self) -> Dict[str, object]:
        if not self.state_path or not self.state_path.exists():
            return {"inode": 0, "offset": 0}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return {"inode": 0, "offset": 0}

    def _save_state(self) -> None:
        if not self.state_path:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(self._state), encoding="utf-8")
