"""Notification engine for class A security events (Этап 6).

The engine subscribes to consensus-fixed class A events and dispatches them
through configured channels:
  - Web UI popups + audio beep (delivered via existing /viz/stream SSE).
  - Email via stdlib smtplib (no extra deps).
  - Telegram via Bot API over aiohttp.

Each channel is independent; failures in one do not block others. The
engine itself is per-node — there is no consensus on who sends what.
"""
from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import ssl
import time
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Sequence

import aiohttp

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NotificationPayload:
    event_id: str
    event_kind: str
    cls: str
    creator: str
    payload: Dict[str, Any]
    ts: float

    @property
    def title(self) -> str:
        return f"[{self.cls}] {self.event_kind}"

    def to_text(self) -> str:
        lines = [
            f"MDRJ-DAG notification",
            f"Event:        {self.event_kind}",
            f"Class:        {self.cls}",
            f"Creator:      {self.creator}",
            f"Event ID:     {self.event_id}",
            f"Timestamp:    {self.ts}",
            "",
            "Payload:",
            json.dumps(self.payload, ensure_ascii=False, indent=2),
        ]
        return "\n".join(lines)


@dataclass(slots=True)
class EmailChannelConfig:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    use_tls: bool = True
    from_addr: str = ""
    to_addrs: List[str] = field(default_factory=list)


@dataclass(slots=True)
class TelegramChannelConfig:
    enabled: bool = False
    bot_token: str = ""
    chat_ids: List[str] = field(default_factory=list)
    timeout_sec: float = 10.0


@dataclass(slots=True)
class NotifierConfig:
    enabled: bool = False
    trigger_classes: List[str] = field(default_factory=lambda: ["A"])
    email: EmailChannelConfig = field(default_factory=EmailChannelConfig)
    telegram: TelegramChannelConfig = field(default_factory=TelegramChannelConfig)


class BaseChannel:
    name: str = "base"

    async def send(self, notification: NotificationPayload) -> bool:
        raise NotImplementedError


class EmailChannel(BaseChannel):
    name = "email"

    def __init__(self, config: EmailChannelConfig) -> None:
        self.config = config
        self.last_error: Optional[str] = None

    async def send(self, notification: NotificationPayload) -> bool:
        if not self.config.enabled:
            return False
        if not self.config.smtp_host or not self.config.from_addr or not self.config.to_addrs:
            self.last_error = "email channel not fully configured"
            return False
        try:
            return await asyncio.to_thread(self._send_blocking, notification)
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.exception("email send failed")
            return False

    def _send_blocking(self, notification: NotificationPayload) -> bool:
        msg = EmailMessage()
        msg["Subject"] = notification.title
        msg["From"] = self.config.from_addr
        msg["To"] = ", ".join(self.config.to_addrs)
        msg.set_content(notification.to_text())
        if self.config.use_tls:
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=15) as smtp:
                context = ssl.create_default_context()
                smtp.starttls(context=context)
                if self.config.smtp_user and self.config.smtp_password:
                    smtp.login(self.config.smtp_user, self.config.smtp_password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=15) as smtp:
                if self.config.smtp_user and self.config.smtp_password:
                    smtp.login(self.config.smtp_user, self.config.smtp_password)
                smtp.send_message(msg)
        self.last_error = None
        return True


class TelegramChannel(BaseChannel):
    name = "telegram"

    def __init__(self, config: TelegramChannelConfig, *, session_factory=None) -> None:
        self.config = config
        self.last_error: Optional[str] = None
        # session_factory lets tests inject a mock; otherwise we create our own.
        self._session_factory = session_factory

    async def send(self, notification: NotificationPayload) -> bool:
        if not self.config.enabled:
            return False
        if not self.config.bot_token or not self.config.chat_ids:
            self.last_error = "telegram channel not fully configured"
            return False
        url = f"https://api.telegram.org/bot{self.config.bot_token}/sendMessage"
        text = f"*{notification.title}*\n```\n{notification.to_text()}\n```"
        try:
            session_ctx = (self._session_factory or aiohttp.ClientSession)()
            async with session_ctx as session:
                for chat_id in self.config.chat_ids:
                    async with session.post(
                        url,
                        json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
                        timeout=aiohttp.ClientTimeout(total=self.config.timeout_sec),
                    ) as resp:
                        if resp.status != 200:
                            body = await resp.text()
                            self.last_error = f"telegram http {resp.status}: {body[:200]}"
                            return False
            self.last_error = None
            return True
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.exception("telegram send failed")
            return False


class NotifierEngine:
    """Per-node notification dispatcher.

    The engine is fed by Node which calls ``ingest_event(event_kind, cls, ...)``
    after a class-A event becomes part of total order. The engine filters
    by configured trigger_classes and dispatches concurrently through all
    enabled channels.
    """

    def __init__(self, config: NotifierConfig) -> None:
        self.config = config
        self.channels: List[BaseChannel] = []
        if config.email.enabled:
            self.channels.append(EmailChannel(config.email))
        if config.telegram.enabled:
            self.channels.append(TelegramChannel(config.telegram))
        self._sent_count = 0
        self._failed_count = 0

    def status(self) -> Dict[str, Any]:
        return {
            "enabled": self.config.enabled,
            "trigger_classes": list(self.config.trigger_classes),
            "channels": [
                {
                    "name": ch.name,
                    "last_error": getattr(ch, "last_error", None),
                }
                for ch in self.channels
            ],
            "sent_count": self._sent_count,
            "failed_count": self._failed_count,
        }

    def should_trigger(self, cls: str) -> bool:
        if not self.config.enabled:
            return False
        return cls in self.config.trigger_classes

    async def dispatch(self, notification: NotificationPayload) -> Dict[str, bool]:
        if not self.config.enabled:
            return {}
        if notification.cls not in self.config.trigger_classes:
            return {}
        results: Dict[str, bool] = {}
        for channel in self.channels:
            try:
                ok = await channel.send(notification)
            except Exception:
                logger.exception("channel %s raised", channel.name)
                ok = False
            results[channel.name] = ok
            if ok:
                self._sent_count += 1
            else:
                self._failed_count += 1
        return results
