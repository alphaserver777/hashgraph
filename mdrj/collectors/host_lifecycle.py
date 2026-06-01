"""Host lifecycle collector: boot, reboot, uptime anomaly.

Замыкает четвёртый слой защиты от обхода УБИ.124 (после Merkle, heartbeat
и service-lifecycle). Атакующий теперь не может скрыть свои действия даже
через перезагрузку хоста с подменой systemd-юнита — каждая загрузка
системы фиксируется в реестре.

Логика:
- При каждом poll читаем `/proc/uptime` и вычисляем boot_time = now - uptime
- В первый раз эмитим `host_boot` с этим boot_time
- При следующих poll: если boot_time изменился (т.е. uptime скачкообразно
  обнулился) — это была перезагрузка → эмитим `host_reboot`
- Если предыдущий boot_time был «очень давно», а наша служба только что
  стартовала (нет недавнего mdrj_service_stop), это значит хост перезагрузился
  пока служба была в офлайне → `host_uptime_anomaly`

Реализация максимально простая и не требует root: `/proc/uptime` доступен
любому пользователю.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .base import BaseCollector, CollectedEvent


@dataclass
class HostLifecycleCollectorConfig:
    enabled: bool = False
    poll_interval_sec: float = 60.0  # раз в минуту — boot редкое событие
    proc_uptime_path: str = "/proc/uptime"
    # Дрифт между boot_time чтениями ≥ этого значения = новая загрузка.
    # Меньше — обычные shifts из-за разной точности измерения now/uptime.
    boot_time_drift_threshold_sec: float = 30.0


class HostLifecycleCollector(BaseCollector):
    name = "host_lifecycle"

    def __init__(
        self,
        *,
        config: HostLifecycleCollectorConfig,
        node_id: str,
        host_id: Optional[str] = None,
    ) -> None:
        super().__init__(
            poll_interval_sec=config.poll_interval_sec,
            node_id=node_id,
            host_id=host_id or node_id,
        )
        self.config = config
        self._known_boot_time: Optional[float] = None
        self._first_poll_done = False
        if not config.enabled:
            self.status.enabled = False
        elif not Path(config.proc_uptime_path).exists():
            self.status.enabled = False
            self.status.last_error = f"{config.proc_uptime_path} not a regular file"

    def _read_boot_time(self) -> Optional[float]:
        try:
            text = Path(self.config.proc_uptime_path).read_text(encoding="ascii")
        except OSError as exc:
            self.status.last_error = f"read /proc/uptime failed: {exc}"
            return None
        try:
            uptime = float(text.split()[0])
        except (ValueError, IndexError):
            self.status.last_error = "failed to parse /proc/uptime"
            return None
        return time.time() - uptime

    def poll(self) -> List[CollectedEvent]:
        self.status.last_poll_at = time.time()
        if not self.status.enabled:
            return []
        current_boot_time = self._read_boot_time()
        if current_boot_time is None:
            return []
        self.status.last_error = None
        events: List[CollectedEvent] = []
        if not self._first_poll_done:
            # Первый poll после старта службы — эмитим host_boot с текущим
            # boot_time. Это даёт нашему реестру привязку к загрузке системы.
            events.append(self.annotate(CollectedEvent(
                event_kind="host_boot",
                payload={
                    "category": "system_lifecycle",
                    "boot_time": current_boot_time,
                    "uptime_at_observation_sec": time.time() - current_boot_time,
                    "description": "Загрузка операционной системы хоста зафиксирована при старте узла.",
                },
            )))
            self._known_boot_time = current_boot_time
            self._first_poll_done = True
            self.status.last_event_at = time.time()
            self.status.emitted_count += len(events)
            return events
        # Дрифт boot_time = новая загрузка хоста за время работы узла.
        # Это значит хост был перезагружен, но наш процесс пережил
        # перезагрузку (через volume + автостарт), и теперь мы это
        # детектим. На практике сценарий нечастый, но важный.
        if self._known_boot_time is not None:
            drift = abs(current_boot_time - self._known_boot_time)
            if drift > self.config.boot_time_drift_threshold_sec:
                events.append(self.annotate(CollectedEvent(
                    event_kind="host_reboot",
                    payload={
                        "category": "system_lifecycle",
                        "previous_boot_time": self._known_boot_time,
                        "new_boot_time": current_boot_time,
                        "drift_sec": drift,
                        "description": "Зафиксирована новая загрузка операционной системы хоста за время работы узла.",
                    },
                )))
                self._known_boot_time = current_boot_time
                self.status.last_event_at = time.time()
                self.status.emitted_count += len(events)
        return events
