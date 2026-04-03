"""Simulation scenarios for MDRJ-DAG visualizer."""
from __future__ import annotations

import random
import secrets
from datetime import datetime
from typing import Dict

from .event_catalog import EVENT_CATALOG


DEMO_SCENARIOS = ("virus", "admin_login", "mac_spoof", "portscan", "heartbeat")
SCENARIOS: Dict[str, Dict[str, object]] = {
    key: {"class": entry["class"], "payload": dict(entry["payload"])}
    for key, entry in EVENT_CATALOG.items()
    if key in DEMO_SCENARIOS
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
