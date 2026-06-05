"""Configuration loader for MDRJ-DAG nodes."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

from .collectors import (
    HostLifecycleCollectorConfig,
    JournaldCollectorConfig,
    LinuxAuditCollectorConfig,
    LinuxFirewallCollectorConfig,
    LinuxProcCollectorConfig,
)
from .agent_relay import AgentRelayConfig
from .discovery import DiscoveryConfig
from .models import NodeProfile, normalize_node_role
from .notifier import EmailChannelConfig, NotifierConfig, TelegramChannelConfig


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
class CollectorsConfig:
    """Optional collectors section in the node config."""
    journald: JournaldCollectorConfig = field(default_factory=JournaldCollectorConfig)
    audit: LinuxAuditCollectorConfig = field(default_factory=LinuxAuditCollectorConfig)
    firewall: LinuxFirewallCollectorConfig = field(default_factory=LinuxFirewallCollectorConfig)
    proc: LinuxProcCollectorConfig = field(default_factory=LinuxProcCollectorConfig)
    host_lifecycle: HostLifecycleCollectorConfig = field(default_factory=HostLifecycleCollectorConfig)


@dataclass(slots=True)
class RetentionConfig:
    """Retention policy for hot storage (Этап 3.b).

    Events covered by a confirmed checkpoint with `round_received <= checkpoint`
    can be moved to the cold path (event_skeletons + optional archive file).
    """
    enabled: bool = False
    max_db_bytes: int = 100 * 1024 * 1024  # 100 MB by default
    max_age_days: int = 30
    keep_class_a: bool = True
    archive_path: Optional[str] = None  # if set, dump pruned events here before delete
    poll_interval_sec: float = 300.0  # 5 minutes


@dataclass(slots=True)
class HeartbeatConfig:
    """Periodic liveness signal (Этап «сигнал жизни», после ADR-0006).

    Each node emits a class C event_kind=heartbeat once per interval_sec,
    irrespective of real security events. The gap between consecutive
    heartbeats from a given node is a witness of that node's continuous
    operation. Missing heartbeats during a suspicious period are a clue
    that the collection pipeline was interrupted — closing the gap that
    UBI.124 would otherwise exploit through service shutdown.
    """
    enabled: bool = False
    interval_sec: float = 300.0  # 5 minutes


@dataclass(slots=True)
class RuntimeConfig:
    """Параметры рантайма для слабых хостов (backpressure / дебаунс)."""
    # Дебаунс пересчёта консенсуса: при 0 — recompute синхронно на каждый
    # persist (как раньше). При >0 — N persist в окне coalesce в один
    # фоновый пересчёт через asyncio.to_thread. Снижает CPU/RSS на
    # gossip-burst в разы при N≥500 событий.
    recompute_debounce_sec: float = 0.0


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
    collectors: CollectorsConfig = field(default_factory=CollectorsConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    notifier: NotifierConfig = field(default_factory=NotifierConfig)
    agent_relay: AgentRelayConfig = field(default_factory=AgentRelayConfig)
    heartbeat: HeartbeatConfig = field(default_factory=HeartbeatConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)

    @property
    def host(self) -> str:
        return self.listen.split(":")[0]

    @property
    def port(self) -> int:
        return int(self.listen.split(":")[1])


def _read_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fp:
        return yaml.safe_load(_expand_env_vars(fp.read()))


ENV_PATTERN = re.compile(r"\$\{(?P<name>[A-Z0-9_]+)(?::-?(?P<default>[^}]*))?\}")


def _expand_env_vars(text: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        name = match.group("name")
        default = match.group("default")
        value = os.environ.get(name)
        if value is not None:
            return value
        return default or ""

    return ENV_PATTERN.sub(_replace, text)


def _parse_peers(raw_peers: object) -> List[str]:
    if raw_peers is None:
        return []
    if isinstance(raw_peers, list):
        return [str(item).strip() for item in raw_peers if str(item).strip()]
    if isinstance(raw_peers, str):
        return [item.strip() for item in raw_peers.split(",") if item.strip()]
    return []


def load_config(path: str | Path) -> NodeConfig:
    raw = _read_yaml(Path(path))
    profile = NodeProfile(
        role=normalize_node_role(raw["profile"]["role"]),
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
    collectors = _parse_collectors(raw.get("collectors", {}) or {})
    retention = _parse_retention(raw.get("retention", {}) or {})
    discovery = _parse_discovery(raw.get("discovery", {}) or {})
    notifier = _parse_notifier(raw.get("notifier", {}) or {})
    agent_relay = _parse_agent_relay(raw.get("agent_relay", {}) or {})
    heartbeat = _parse_heartbeat(raw.get("heartbeat", {}) or {})
    runtime = _parse_runtime(raw.get("runtime", {}) or {})
    return NodeConfig(
        node_id=raw["node_id"],
        listen=raw["listen"],
        peers=_parse_peers(raw.get("peers", [])),
        profile=profile,
        gossip=gossip,
        prioritization=prioritization,
        security=security,
        storage=storage,
        linux_ingest=linux_ingest,
        collectors=collectors,
        retention=retention,
        discovery=discovery,
        notifier=notifier,
        agent_relay=agent_relay,
        heartbeat=heartbeat,
        runtime=runtime,
    )


def _parse_runtime(raw: dict) -> RuntimeConfig:
    return RuntimeConfig(
        recompute_debounce_sec=float(raw.get("recompute_debounce_sec", 0.0)),
    )


def _parse_heartbeat(raw: dict) -> HeartbeatConfig:
    return HeartbeatConfig(
        enabled=bool(raw.get("enabled", False)),
        interval_sec=float(raw.get("interval_sec", 300.0)),
    )


def _parse_agent_relay(raw: dict) -> AgentRelayConfig:
    return AgentRelayConfig(
        enabled=bool(raw.get("enabled", False)),
        relay_url=str(raw.get("relay_url", "")),
        timeout_sec=float(raw.get("timeout_sec", 5.0)),
        max_retries=int(raw.get("max_retries", 3)),
        retry_backoff_sec=float(raw.get("retry_backoff_sec", 1.0)),
    )


def _parse_notifier(raw: dict) -> NotifierConfig:
    email_raw = raw.get("email", {}) or {}
    telegram_raw = raw.get("telegram", {}) or {}
    return NotifierConfig(
        enabled=bool(raw.get("enabled", False)),
        trigger_classes=list(raw.get("trigger_classes", ["A"])),
        email=EmailChannelConfig(
            enabled=bool(email_raw.get("enabled", False)),
            smtp_host=str(email_raw.get("smtp_host", "")),
            smtp_port=int(email_raw.get("smtp_port", 587)),
            smtp_user=email_raw.get("smtp_user"),
            smtp_password=email_raw.get("smtp_password"),
            use_tls=bool(email_raw.get("use_tls", True)),
            from_addr=str(email_raw.get("from_addr", "")),
            to_addrs=list(email_raw.get("to_addrs", [])),
        ),
        telegram=TelegramChannelConfig(
            enabled=bool(telegram_raw.get("enabled", False)),
            bot_token=str(telegram_raw.get("bot_token", "")),
            chat_ids=[str(c) for c in telegram_raw.get("chat_ids", [])],
            timeout_sec=float(telegram_raw.get("timeout_sec", 10.0)),
        ),
    )


def _parse_discovery(raw: dict) -> DiscoveryConfig:
    return DiscoveryConfig(
        mode=str(raw.get("mode", "disabled")),
        poll_interval_sec=float(raw.get("poll_interval_sec", 10.0)),
        auto_approve_discovered=bool(raw.get("auto_approve_discovered", False)),
        advertise_port=int(raw["advertise_port"]) if raw.get("advertise_port") is not None else None,
        k8s_service=raw.get("k8s_service"),
        k8s_target_port=int(raw.get("k8s_target_port", 9001)),
    )


def _parse_retention(raw: dict) -> RetentionConfig:
    return RetentionConfig(
        enabled=bool(raw.get("enabled", False)),
        max_db_bytes=int(raw.get("max_db_bytes", 100 * 1024 * 1024)),
        max_age_days=int(raw.get("max_age_days", 30)),
        keep_class_a=bool(raw.get("keep_class_a", True)),
        archive_path=raw.get("archive_path"),
        poll_interval_sec=float(raw.get("poll_interval_sec", 300.0)),
    )


def _parse_collectors(raw: dict) -> CollectorsConfig:
    def _intlist(values):
        return [int(v) for v in values or []]

    journald_raw = raw.get("journald", {}) or {}
    audit_raw = raw.get("audit", {}) or {}
    firewall_raw = raw.get("firewall", {}) or {}
    proc_raw = raw.get("proc", {}) or {}
    host_raw = raw.get("host_lifecycle", {}) or {}

    journald = JournaldCollectorConfig(
        enabled=bool(journald_raw.get("enabled", False)),
        units=list(journald_raw.get("units", ["ssh.service", "sshd.service"])),
        burst_window_sec=int(journald_raw.get("burst_window_sec", 60)),
        burst_threshold=int(journald_raw.get("burst_threshold", 10)),
        poll_interval_sec=float(journald_raw.get("poll_interval_sec", 5.0)),
    )
    audit = LinuxAuditCollectorConfig(
        enabled=bool(audit_raw.get("enabled", False)),
        watch_paths=list(audit_raw.get("watch_paths", LinuxAuditCollectorConfig().watch_paths)),
        poll_interval_sec=float(audit_raw.get("poll_interval_sec", 5.0)),
        hash_max_bytes=int(audit_raw.get("hash_max_bytes", 1_048_576)),
    )
    firewall = LinuxFirewallCollectorConfig(
        enabled=bool(firewall_raw.get("enabled", False)),
        tool=str(firewall_raw.get("tool", "iptables-save")),
        poll_interval_sec=float(firewall_raw.get("poll_interval_sec", 10.0)),
    )
    proc = LinuxProcCollectorConfig(
        enabled=bool(proc_raw.get("enabled", False)),
        blocklist=list(proc_raw.get("blocklist", LinuxProcCollectorConfig().blocklist)),
        privileged_uids=_intlist(proc_raw.get("privileged_uids", [0])),
        poll_interval_sec=float(proc_raw.get("poll_interval_sec", 3.0)),
        proc_root=str(proc_raw.get("proc_root", "/proc")),
    )
    host_lifecycle = HostLifecycleCollectorConfig(
        enabled=bool(host_raw.get("enabled", False)),
        poll_interval_sec=float(host_raw.get("poll_interval_sec", 60.0)),
        proc_uptime_path=str(host_raw.get("proc_uptime_path", "/proc/uptime")),
        boot_time_drift_threshold_sec=float(host_raw.get("boot_time_drift_threshold_sec", 30.0)),
    )
    return CollectorsConfig(
        journald=journald,
        audit=audit,
        firewall=firewall,
        proc=proc,
        host_lifecycle=host_lifecycle,
    )
