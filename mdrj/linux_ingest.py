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


SYSLOG_SSH_ACCEPTED_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd(?:-session)?(?:\[\d+\])?:\s+"
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>[\w.@-]+)\s+from\s+"
    r"(?P<source_ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)"
)

ISO_SSH_ACCEPTED_RE = re.compile(
    r"^(?P<occurred_at>\d{4}-\d{2}-\d{2}T[^\s]+)\s+"
    r"(?P<host>\S+)\s+"
    r"sshd(?:-session)?(?:\[\d+\])?:\s+"
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>[\w.@-]+)\s+from\s+"
    r"(?P<source_ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)"
)

# Неуспешный SSH-вход (оба формата времени). Источник для агрегации
# failed_login_burst — единичные fail не эмитим (шум от ботов), эмитим
# одно событие класса A при превышении порога за окно.
SSH_FAILED_RE = re.compile(
    r"sshd(?:-session)?(?:\[\d+\])?:\s+"
    r"Failed\s+password\s+for\s+(?:invalid user\s+)?(?P<user>[\w.@-]+)\s+from\s+"
    r"(?P<source_ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)"
)

# Повышение привилегий: успешная sudo-сессия или su к root.
SUDO_SESSION_RE = re.compile(
    r"sudo(?:\[\d+\])?:\s+pam_unix\(sudo:session\):\s+session opened for user\s+(?P<target>[\w.@-]+)"
    r"(?:\(uid=\d+\))?\s+by\s+(?P<actor>[\w.@-]*)"
)
SU_SESSION_RE = re.compile(
    r"\bsu(?:\[\d+\])?:\s+pam_unix\(su(?:-l)?:session\):\s+session opened for user\s+(?P<target>[\w.@-]+)"
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
        # Скользящее окно неудачных входов по source_ip для агрегации
        # failed_login_burst. Порог и окно — разумные дефолты.
        self._failed_window: Dict[str, List[float]] = {}
        self._failed_burst_threshold = 5
        self._failed_burst_window_sec = 120.0
        self._failed_burst_emitted_at: Dict[str, float] = {}

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
        match = ISO_SSH_ACCEPTED_RE.match(line)
        timestamp_kind = "iso"
        if not match:
            match = SYSLOG_SSH_ACCEPTED_RE.match(line)
            timestamp_kind = "syslog"
        if not match:
            # Не успешный вход — пробуем прочие парсеры (failed burst,
            # повышение привилегий). Они не зависят от admin_users-фильтра.
            return self._parse_other(line, line_offset, collected_at_ts)

        principal = match.group("user")
        privilege_scope = self._privilege_scope(principal)
        if privilege_scope is None:
            return None

        occurred_at = self._parse_timestamp(match, timestamp_kind)
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

    def _parse_other(
        self,
        line: str,
        line_offset: int,
        collected_at_ts: float,
    ) -> Optional[Dict[str, object]]:
        """Парсеры неуспешных входов (burst) и повышения привилегий."""
        collected_at = datetime.fromtimestamp(collected_at_ts).isoformat(timespec="seconds") + "Z"
        raw_ref = f"{self.auth_log_path}:{line_offset}"

        # 1. Failed password → агрегация в failed_login_burst.
        m = SSH_FAILED_RE.search(line)
        if m:
            ip = m.group("source_ip")
            window = self._failed_window.setdefault(ip, [])
            window.append(collected_at_ts)
            cutoff = collected_at_ts - self._failed_burst_window_sec
            window[:] = [t for t in window if t >= cutoff]
            if len(window) >= self._failed_burst_threshold:
                # Не чаще одного burst-события на окно для одного ip.
                last_emit = self._failed_burst_emitted_at.get(ip, 0.0)
                if collected_at_ts - last_emit < self._failed_burst_window_sec:
                    return None
                self._failed_burst_emitted_at[ip] = collected_at_ts
                count = len(window)
                window.clear()
                return {
                    "event_kind": "failed_login_burst",
                    "class": "A",
                    "host_id": self.host_id,
                    "node_id": self.node_id,
                    "collected_at": collected_at,
                    "source_ip": ip,
                    "target_service": "sshd",
                    "result": "failure",
                    "failed_count": count,
                    "window_sec": self._failed_burst_window_sec,
                    "raw_ref": raw_ref,
                    "title": f"Серия неудачных входов с {ip}",
                    "description": (
                        f"Зафиксировано ≥{self._failed_burst_threshold} неудачных "
                        f"SSH-входов с адреса {ip} за {int(self._failed_burst_window_sec)}с — "
                        "признак автоматизированного подбора пароля."
                    ),
                    "category": "authentication",
                    "context": {"source_type": self.config.source_type, "raw_line": line},
                }
            return None

        # 2. Повышение привилегий: sudo / su сессия.
        m = SUDO_SESSION_RE.search(line)
        mechanism = None
        target = actor = None
        if m:
            mechanism = "sudo"
            target = m.group("target")
            actor = m.group("actor") or ""
        else:
            m = SU_SESSION_RE.search(line)
            if m:
                mechanism = "su"
                target = m.group("target")
                actor = ""
        if mechanism and target == "root":
            return {
                "event_kind": "privilege_escalation",
                "class": "A",
                "host_id": self.host_id,
                "node_id": self.node_id,
                "collected_at": collected_at,
                "mechanism": mechanism,
                "target_user": target,
                "actor_user": actor,
                "raw_ref": raw_ref,
                "title": f"Повышение привилегий через {mechanism} до {target}",
                "description": (
                    f"Открыта привилегированная сессия ({mechanism}) для {target}"
                    + (f" пользователем {actor}" if actor else "") + "."
                ),
                "category": "authentication",
                "context": {"source_type": self.config.source_type, "raw_line": line},
            }
        return None

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

    def _parse_timestamp(self, match: re.Match[str], timestamp_kind: str) -> str:
        if timestamp_kind == "iso":
            occurred_at = match.group("occurred_at")
            return datetime.fromisoformat(occurred_at).isoformat(timespec="seconds")
        now = datetime.now()
        candidate = datetime.strptime(
            f"{now.year} {match.group('month')} {match.group('day')} {match.group('clock')}",
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
