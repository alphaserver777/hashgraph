"""Linux iptables/nftables firewall rule change collector.

Periodically runs `iptables-save` (or `nft list ruleset`) and emits
`iptables_rule_changed` when the canonical dump changes between polls.
This is a black-box differ — it does not parse rule semantics, only
detects mutations.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional

from .base import BaseCollector, CollectedEvent


@dataclass
class LinuxFirewallCollectorConfig:
    enabled: bool = False
    tool: str = "iptables-save"  # or "nft"
    poll_interval_sec: float = 10.0


class LinuxFirewallCollector(BaseCollector):
    name = "linux_firewall"

    def __init__(
        self,
        *,
        config: LinuxFirewallCollectorConfig,
        node_id: str,
        host_id: Optional[str] = None,
    ) -> None:
        super().__init__(
            poll_interval_sec=config.poll_interval_sec,
            node_id=node_id,
            host_id=host_id or node_id,
        )
        self.config = config
        self._last_digest: Optional[str] = None
        self._first_poll = True
        if not shutil.which(self._cmd[0]):
            self.status.enabled = False
            self.status.last_error = f"{self._cmd[0]} not available"

    @property
    def _cmd(self) -> List[str]:
        if self.config.tool == "nft":
            return ["nft", "-a", "list", "ruleset"]
        return ["iptables-save"]

    def poll(self) -> List[CollectedEvent]:
        self.status.last_poll_at = time.time()
        if not self.status.enabled:
            return []
        try:
            result = subprocess.run(self._cmd, capture_output=True, text=True, timeout=10)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            self.status.last_error = f"{type(exc).__name__}: {exc}"
            return []
        if result.returncode != 0:
            self.status.last_error = f"{self._cmd[0]} exit {result.returncode}: {result.stderr.strip()[:200]}"
            return []
        self.status.last_error = None
        digest = hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()
        previous = self._last_digest
        self._last_digest = digest
        if self._first_poll:
            self._first_poll = False
            return []
        if previous == digest:
            return []
        event = self.annotate(
            CollectedEvent(
                event_kind="iptables_rule_changed",
                payload={
                    "category": "network",
                    "tool": self.config.tool,
                    "previous_digest": previous,
                    "current_digest": digest,
                    "ruleset_bytes": len(result.stdout),
                },
            )
        )
        self.status.last_event_at = time.time()
        self.status.emitted_count += 1
        return [event]
