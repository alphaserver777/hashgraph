"""Executable mirror of the event classification policy document."""
from __future__ import annotations

from typing import Dict, Mapping

from .models import EventClass


# Keep this file synchronized with docs/event-classification.md.
EVENT_CATALOG: Dict[str, Dict[str, object]] = {
    "virus": {
        "class": EventClass.A,
        "title": "Обнаружен вирус на узле",
        "payload": {
            "category": "malware",
            "description": "Обнаружен подозрительный исполняемый файл",
            "severity": "high",
        },
    },
    "admin_login": {
        "class": EventClass.B,
        "title": "Удалённый вход администратора",
        "payload": {
            "category": "authentication",
            "description": "Удалённый вход администратора",
            "source_ip": "192.0.2.15",
        },
    },
    "mac_spoof": {
        "class": EventClass.A,
        "title": "Попытка MAC-spoofing",
        "payload": {
            "category": "network",
            "description": "Попытка подмены MAC-адреса",
        },
    },
    "portscan": {
        "class": EventClass.B,
        "title": "Аномальный порт-скан",
        "payload": {
            "category": "network",
            "description": "Аномальный порт-скан внешним узлом",
        },
    },
    "heartbeat": {
        "class": EventClass.C,
        "title": "Тестовый heartbeat",
        "payload": {
            "category": "diagnostic",
            "description": "Плановый heartbeat от панели мониторинга",
        },
    },
}


def event_catalog() -> Mapping[str, Dict[str, object]]:
    """Return the configured catalog of known event kinds."""
    return EVENT_CATALOG


def event_class_for(kind: str) -> EventClass:
    """Return MDRJ event class for a known event kind."""
    entry = EVENT_CATALOG[kind]
    return entry["class"]  # type: ignore[return-value]
