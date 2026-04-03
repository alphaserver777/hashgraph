"""Configuration loader for MDRJ-DAG nodes."""
from __future__ import annotations

from dataclasses import dataclass, field
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
class LinuxIngestConfig:
    enabled: bool = False
    source_type: str = "auth_log_file"
    auth_log_path: Optional[str] = None
    poll_interval_sec: float = 2.0
    host_id: Optional[str] = None
    admin_users: List[str] = field(default_factory=list)
    privileged_groups: List[str] = field(default_factory=list)
    state_path: Optional[str] = None


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
    linux_ingest: LinuxIngestConfig = field(default_factory=LinuxIngestConfig)

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
    linux_raw = raw.get("linux_ingest", {}) or {}
    linux_ingest = LinuxIngestConfig(
        enabled=bool(linux_raw.get("enabled", False)),
        source_type=str(linux_raw.get("source_type", "auth_log_file")),
        auth_log_path=linux_raw.get("auth_log_path"),
        poll_interval_sec=float(linux_raw.get("poll_interval_sec", 2.0)),
        host_id=linux_raw.get("host_id"),
        admin_users=list(linux_raw.get("admin_users", [])),
        privileged_groups=list(linux_raw.get("privileged_groups", [])),
        state_path=linux_raw.get("state_path"),
    )
    return NodeConfig(
        node_id=raw["node_id"],
        listen=raw["listen"],
        peers=list(raw.get("peers", [])),
        profile=profile,
        gossip=gossip,
        prioritization=prioritization,
        security=security,
        storage=storage,
        linux_ingest=linux_ingest,
    )
