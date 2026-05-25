"""Tests for notification engine (Этап 6)."""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Any, Dict, List

import pytest

from mdrj.notifier import (
    BaseChannel,
    EmailChannelConfig,
    NotificationPayload,
    NotifierConfig,
    NotifierEngine,
    TelegramChannel,
    TelegramChannelConfig,
)


def _make_payload(cls: str = "A", event_kind: str = "virus") -> NotificationPayload:
    return NotificationPayload(
        event_id="abcd1234",
        event_kind=event_kind,
        cls=cls,
        creator="node-1",
        payload={"event_kind": event_kind, "severity": "high"},
        ts=1779000000.0,
    )


class _RecordingChannel(BaseChannel):
    name = "record"

    def __init__(self, *, result: bool = True) -> None:
        self.result = result
        self.received: List[NotificationPayload] = []
        self.last_error = None

    async def send(self, notification: NotificationPayload) -> bool:
        self.received.append(notification)
        return self.result


def test_should_trigger_respects_config():
    engine = NotifierEngine(NotifierConfig(enabled=True, trigger_classes=["A"]))
    assert engine.should_trigger("A") is True
    assert engine.should_trigger("B") is False
    engine.config.enabled = False
    assert engine.should_trigger("A") is False


@pytest.mark.asyncio
async def test_dispatch_skips_when_engine_disabled():
    engine = NotifierEngine(NotifierConfig(enabled=False, trigger_classes=["A"]))
    channel = _RecordingChannel()
    engine.channels = [channel]
    result = await engine.dispatch(_make_payload())
    assert result == {}
    assert channel.received == []


@pytest.mark.asyncio
async def test_dispatch_routes_to_all_enabled_channels():
    engine = NotifierEngine(NotifierConfig(enabled=True, trigger_classes=["A"]))
    a = _RecordingChannel()
    b = _RecordingChannel()
    a.name = "alpha"
    b.name = "beta"
    engine.channels = [a, b]
    result = await engine.dispatch(_make_payload())
    assert result == {"alpha": True, "beta": True}
    assert len(a.received) == 1 and len(b.received) == 1
    status = engine.status()
    assert status["sent_count"] == 2
    assert status["failed_count"] == 0


@pytest.mark.asyncio
async def test_dispatch_continues_when_one_channel_fails():
    engine = NotifierEngine(NotifierConfig(enabled=True, trigger_classes=["A"]))
    good = _RecordingChannel(result=True)
    bad = _RecordingChannel(result=False)
    good.name = "good"
    bad.name = "bad"
    engine.channels = [bad, good]
    result = await engine.dispatch(_make_payload())
    assert result == {"bad": False, "good": True}
    assert len(good.received) == 1
    assert len(bad.received) == 1


@pytest.mark.asyncio
async def test_dispatch_filters_by_class():
    engine = NotifierEngine(NotifierConfig(enabled=True, trigger_classes=["A"]))
    channel = _RecordingChannel()
    engine.channels = [channel]
    await engine.dispatch(_make_payload(cls="B"))
    assert channel.received == []
    await engine.dispatch(_make_payload(cls="A"))
    assert len(channel.received) == 1


@pytest.mark.asyncio
async def test_telegram_channel_disabled_short_circuits():
    cfg = TelegramChannelConfig(enabled=False, bot_token="x", chat_ids=["1"])
    channel = TelegramChannel(cfg)
    assert await channel.send(_make_payload()) is False


@pytest.mark.asyncio
async def test_telegram_channel_misconfigured_records_error():
    cfg = TelegramChannelConfig(enabled=True, bot_token="", chat_ids=[])
    channel = TelegramChannel(cfg)
    assert await channel.send(_make_payload()) is False
    assert "not fully configured" in (channel.last_error or "")


@pytest.mark.asyncio
async def test_telegram_channel_send_via_mock_session():
    """Verify the request body shape without touching the real network."""
    sent: List[Dict[str, Any]] = []

    class _MockResponse:
        status = 200
        async def text(self) -> str:
            return "ok"
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a, **kw):
            return None

    class _MockSession:
        def __init__(self):
            self.closed = False
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a, **kw):
            self.closed = True
        def post(self, url, **kw):
            sent.append({"url": url, **kw})
            return _MockResponse()

    cfg = TelegramChannelConfig(enabled=True, bot_token="TOKEN", chat_ids=["111", "222"])
    channel = TelegramChannel(cfg, session_factory=_MockSession)
    ok = await channel.send(_make_payload(event_kind="critical_security_error"))
    assert ok is True
    assert len(sent) == 2
    assert "/botTOKEN/sendMessage" in sent[0]["url"]
    body = sent[0]["json"]
    assert body["chat_id"] == "111"
    assert "critical_security_error" in body["text"]


def test_notification_payload_to_text_contains_key_fields():
    payload = _make_payload()
    text = payload.to_text()
    assert "virus" in text
    assert "node-1" in text
    assert "abcd1234" in text
    assert "Payload:" in text


def test_engine_status_includes_channel_metadata():
    engine = NotifierEngine(NotifierConfig(
        enabled=True,
        trigger_classes=["A", "B"],
        email=EmailChannelConfig(enabled=False),
        telegram=TelegramChannelConfig(enabled=True, bot_token="t", chat_ids=["1"]),
    ))
    status = engine.status()
    assert status["enabled"] is True
    assert "A" in status["trigger_classes"]
    assert "B" in status["trigger_classes"]
    assert any(ch["name"] == "telegram" for ch in status["channels"])
