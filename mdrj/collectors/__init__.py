"""Cross-platform security event collectors for MDRJ-DAG nodes.

Each collector reads from a specific source (auth.log, journald, audit, etc.),
normalizes events to a payload dict containing `event_kind`, and returns them
via `poll()`. The Node orchestrates collectors and routes their output through
`emit_event` so the resulting class A/B/C is derived from the central
event_catalog.
"""
from __future__ import annotations

from .base import BaseCollector, CollectedEvent, CollectorStatus
from .linux_audit import LinuxAuditCollector, LinuxAuditCollectorConfig
from .linux_firewall import LinuxFirewallCollector, LinuxFirewallCollectorConfig
from .linux_journald import JournaldCollectorConfig, LinuxJournaldCollector
from .linux_proc import LinuxProcCollector, LinuxProcCollectorConfig

# NOTE: LinuxAuthCollector intentionally NOT re-exported here. It wraps
# mdrj.linux_ingest.LinuxAuthLogIngestor, which itself imports from
# mdrj.config — and mdrj.config imports collector configs from this
# package, so re-exporting it would create a circular import.
# Import it directly as `from mdrj.collectors.linux_auth import LinuxAuthCollector`.

__all__ = [
    "BaseCollector",
    "CollectedEvent",
    "CollectorStatus",
    "JournaldCollectorConfig",
    "LinuxAuditCollector",
    "LinuxAuditCollectorConfig",
    "LinuxFirewallCollector",
    "LinuxFirewallCollectorConfig",
    "LinuxJournaldCollector",
    "LinuxProcCollector",
    "LinuxProcCollectorConfig",
]
