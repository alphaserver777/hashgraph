"""Linux auth.log collector: wraps the existing LinuxAuthLogIngestor."""
from __future__ import annotations

import time
from typing import TYPE_CHECKING, List, Optional

from ..linux_ingest import LinuxAuthLogIngestor
from .base import BaseCollector, CollectedEvent

if TYPE_CHECKING:
    from ..config import LinuxIngestConfig


class LinuxAuthCollector(BaseCollector):
    """Detect successful administrative SSH logins via auth.log tailing.

    Thin adapter over `mdrj.linux_ingest.LinuxAuthLogIngestor` to fit the
    collectors framework. The underlying parser is kept intact for
    compatibility with `tests/test_linux_ingest.py`.
    """

    name = "linux_auth"

    def __init__(
        self,
        *,
        config: "LinuxIngestConfig",
        node_id: str,
        default_state_path: Optional[str] = None,
        host_id: Optional[str] = None,
    ) -> None:
        super().__init__(
            poll_interval_sec=config.poll_interval_sec,
            node_id=node_id,
            host_id=host_id or config.host_id or node_id,
        )
        self._ingestor = LinuxAuthLogIngestor(
            config=config,
            node_id=node_id,
            default_state_path=default_state_path,
        )

    def poll(self) -> List[CollectedEvent]:
        self.status.last_poll_at = time.time()
        try:
            raw = self._ingestor.poll()
        except FileNotFoundError as exc:
            self.status.last_error = str(exc)
            return []
        except Exception as exc:
            self.status.last_error = f"{type(exc).__name__}: {exc}"
            self.logger.exception("linux_auth poll failed")
            return []
        self.status.last_error = None
        events: List[CollectedEvent] = []
        for record in raw:
            event_kind = str(record.get("event_kind") or "admin_ssh_login_success")
            payload = dict(record)
            events.append(self.annotate(CollectedEvent(event_kind=event_kind, payload=payload)))
        if events:
            self.status.last_event_at = time.time()
            self.status.emitted_count += len(events)
        return events
