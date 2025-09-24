"""Configuration loader for MDRJ-DAG nodes."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yaml

from .models import NodeProfile


@dataclass(slots=True)
class GossipConfig:
    period_sec: float
    fan_out: int


@dataclass(slots=True)
class PrioritizationConfig:
    level_threshold_B: str
    max_batch_bytes: int


@dataclass(slots=True)
class SecurityConfig:
    hmac_key: Optional[str]


@dataclass(slots=True)
class StorageConfig:
    sqlite_path: str


@dataclass(slots=True)
class NodeConfig:
    node_id: str
    listen: str
    peers: List[str]
    profile: NodeProfile
    gossip: GossipConfig
    prioritization: PrioritizationConfig
    security: SecurityConfig
    storage: StorageConfig

    @property
    def host(self) -> str:
        return self.listen.split(":")[0]

    @property
    def port(self) -> int:
        return int(self.listen.split(":")[1])


def _read_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fp:
        return yaml.safe_load(fp)


def load_config(path: str | Path) -> NodeConfig:
    raw = _read_yaml(Path(path))
    profile = NodeProfile(
        role=raw["profile"]["role"],
        memory_mb=int(raw["profile"]["memory_mb"]),
        bw_kbps=int(raw["profile"]["bw_kbps"]),
        cpu_quota=float(raw["profile"].get("cpu_quota", 1.0)),
        threat_level=raw["profile"]["threat_level"],
    )
    gossip = GossipConfig(
        period_sec=float(raw["gossip"].get("period_sec", 1.0)),
        fan_out=int(raw["gossip"].get("fan_out", 2)),
    )
    prioritization = PrioritizationConfig(
        level_threshold_B=raw["prioritization"].get("level_threshold_B", "ELEV"),
        max_batch_bytes=int(raw["prioritization"].get("max_batch_bytes", 32768)),
    )
    security = SecurityConfig(hmac_key=raw.get("security", {}).get("hmac_key"))
    storage = StorageConfig(sqlite_path=raw["storage"]["sqlite_path"])
    return NodeConfig(
        node_id=raw["node_id"],
        listen=raw["listen"],
        peers=list(raw.get("peers", [])),
        profile=profile,
        gossip=gossip,
        prioritization=prioritization,
        security=security,
        storage=storage,
    )

