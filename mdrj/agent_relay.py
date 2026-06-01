"""Remote agent relay for Scenario 1 (centralized A1 baseline).

When enabled, the node collects events locally via the existing collectors
framework but forwards every event over HTTP to the centralized collector
instead of writing it into its own DAG. There is no local DAG, no gossip,
no checkpoints. This is the classic SIEM-agent model.

This module exists for one purpose: to let the same code base run both
Scenario 1 (A1, centralized) and Scenario 2 (A4, distributed) for a fair
side-by-side comparison.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac as _hmac
import json
import logging
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AgentRelayConfig:
    enabled: bool = False
    relay_url: str = ""  # http://central:9001/event/emit
    timeout_sec: float = 5.0
    max_retries: int = 3
    retry_backoff_sec: float = 1.0


class AgentRelayClient:
    """Push events to a remote central collector.

    Tracks per-channel statistics so the experiment harness can compute K_d
    (delivery rate of significant events) directly from agent metrics.
    """

    def __init__(self, config: AgentRelayConfig, *, hmac_key: Optional[str], session_factory=None) -> None:
        self.config = config
        self.hmac_key = hmac_key
        self._session_factory = session_factory
        self.sent_count = 0
        self.failed_count = 0
        self.last_error: Optional[str] = None
        self.last_sent_at: Optional[float] = None

    async def send(self, *, event_kind: str, cls: str, payload: dict) -> bool:
        if not self.config.enabled:
            return False
        if not self.config.relay_url:
            self.last_error = "agent_relay.relay_url not set"
            return False

        body_dict = {"event_kind": event_kind, "payload": dict(payload)}
        body = json.dumps(body_dict).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.hmac_key:
            sig = _hmac.new(self.hmac_key.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-MDRJ-Sig"] = sig

        import aiohttp  # imported lazily so unit tests can monkey-patch

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.config.max_retries + 1):
            try:
                session_ctx = (self._session_factory or aiohttp.ClientSession)()
                async with session_ctx as session:
                    async with session.post(
                        self.config.relay_url,
                        data=body,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=self.config.timeout_sec),
                    ) as resp:
                        if 200 <= resp.status < 300:
                            self.sent_count += 1
                            self.last_sent_at = time.time()
                            self.last_error = None
                            return True
                        body_text = (await resp.text())[:200]
                        self.last_error = f"http {resp.status}: {body_text}"
            except Exception as exc:
                last_exc = exc
                self.last_error = f"{type(exc).__name__}: {exc}"
            if attempt < self.config.max_retries:
                await asyncio.sleep(self.config.retry_backoff_sec * attempt)

        self.failed_count += 1
        if last_exc is not None:
            logger.warning("agent relay send failed after %d attempts: %s", self.config.max_retries, last_exc)
        return False

    def status(self) -> dict:
        return {
            "enabled": self.config.enabled,
            "relay_url": self.config.relay_url,
            "sent_count": self.sent_count,
            "failed_count": self.failed_count,
            "last_error": self.last_error,
            "last_sent_at": self.last_sent_at,
        }
