"""Simulation scenarios for MDRJ-DAG visualizer."""
from __future__ import annotations

import random
import secrets
from datetime import datetime
from typing import Dict

from .models import EventClass


SCENARIOS: Dict[str, Dict[str, object]] = {
    "virus": {
        "class": EventClass.A,
        "payload": {
            "category": "malware",
            "description": "Обнаружен подозрительный исполняемый файл",
            "severity": "high",
        },
    },
    "admin_login": {
        "class": EventClass.B,
        "payload": {
            "category": "authentication",
            "description": "Удалённый вход администратора",
            "source_ip": "192.0.2.15",
        },
    },
    "mac_spoof": {
        "class": EventClass.A,
        "payload": {
            "category": "network",
            "description": "Попытка подмены MAC-адреса",
        },
    },
    "portscan": {
        "class": EventClass.B,
        "payload": {
            "category": "network",
            "description": "Аномальный порт-скан внешним узлом",
        },
    },
    "heartbeat": {
        "class": EventClass.C,
        "payload": {
            "category": "diagnostic",
            "description": "Плановый heartbeat от панели мониторинга",
        },
    },
}


def scenario_payload(key: str) -> Dict[str, object]:
    """Return event class name and payload for the simulation scenario."""
    entry = SCENARIOS[key]
    payload = dict(entry["payload"])
    payload.update(
        {
            "scenario": key,
            "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
            "simulation_id": secrets.token_hex(6),
            "confidence": round(random.uniform(0.6, 0.99), 3),
        }
    )
    return {"class": entry["class"], "payload": payload}
