"""Executable mirror of the event classification policy document.

Источник правды — `data/event_catalog.json` (читается при импорте).
Если JSON-файл недоступен, используется встроенный fallback ниже
(сохранён для обратной совместимости и для контекстов где файл
не пробрасывается, например при сборке колеса для PyPI).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Mapping, Optional

from .models import EventClass

logger = logging.getLogger(__name__)

# Метаданные с обоснованиями (rationale, linked_threats, added_by)
# загружаются из JSON и доступны через event_metadata().
_CATALOG_METADATA: Dict[str, Dict[str, object]] = {}


def _candidate_json_paths() -> List[Path]:
    """Возможные расположения data/event_catalog.json."""
    here = Path(__file__).resolve()
    return [
        here.parent.parent / "data" / "event_catalog.json",  # development repo
        Path("/etc/mdrj/event_catalog.json"),  # системный конфиг
        Path("/opt/mdrj/data/event_catalog.json"),  # production install
    ]


def _load_from_json() -> Optional[Dict[str, Dict[str, object]]]:
    """Прочитать каталог из JSON. None если файл не найден или невалиден."""
    for path in _candidate_json_paths():
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            logger.exception("failed to read event catalog from %s", path)
            continue
        events_section = data.get("events") if isinstance(data, dict) else None
        if not isinstance(events_section, dict):
            logger.warning("event catalog at %s has no 'events' section", path)
            continue
        runtime: Dict[str, Dict[str, object]] = {}
        for kind, descriptor in events_section.items():
            if not isinstance(descriptor, dict):
                continue
            try:
                cls = EventClass.from_str(str(descriptor.get("class", "")))
            except ValueError:
                logger.warning("event '%s' in catalog has invalid class; skipped", kind)
                continue
            title = str(descriptor.get("title", kind))
            category = str(descriptor.get("category", "other"))
            runtime[kind] = {
                "class": cls,
                "title": title,
                "payload": {
                    "category": category,
                },
            }
            # Сохраняем расширенные метаданные отдельно — payload остаётся
            # лёгким для эмиссии, а описание/обоснование доступно через API.
            _CATALOG_METADATA[kind] = {
                "class": cls.value,
                "title": title,
                "category": category,
                "rationale": str(descriptor.get("rationale", "")),
                "linked_threats": list(descriptor.get("linked_threats", []) or []),
                "added_by": str(descriptor.get("added_by", "")),
            }
        if runtime:
            logger.info("loaded %d event kinds from %s", len(runtime), path)
            return runtime
    return None


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
    "admin_ssh_login_success": {
        "class": EventClass.A,
        "title": "Успешный административный SSH-вход",
        "payload": {
            "category": "authentication",
            "event_kind": "admin_ssh_login_success",
            "target_service": "sshd",
            "result": "success",
        },
    },
    "admin_login_failure": {
        "class": EventClass.A,
        "title": "Неудачная попытка входа администратора",
        "payload": {
            "category": "authentication",
            "result": "failure",
        },
    },
    "failed_login_burst": {
        "class": EventClass.A,
        "title": "Серия неудачных попыток входа",
        "payload": {
            "category": "authentication",
            "description": "Превышен порог неудачных попыток входа за окно времени",
        },
    },
    "remote_login_rdp": {
        "class": EventClass.B,
        "title": "Удалённый вход через RDP",
        "payload": {
            "category": "authentication",
            "target_service": "rdp",
        },
    },
    "critical_file_modified": {
        "class": EventClass.A,
        "title": "Изменение критического системного файла",
        "payload": {
            "category": "integrity",
            "description": "Зафиксировано изменение файла из списка критических",
        },
    },
    "windows_registry_modified": {
        "class": EventClass.A,
        "title": "Изменение критического ключа реестра Windows",
        "payload": {
            "category": "integrity",
            "description": "Зафиксировано изменение ключа реестра из списка критических",
        },
    },
    "privileged_process_started": {
        "class": EventClass.B,
        "title": "Запуск процесса с повышенными привилегиями",
        "payload": {
            "category": "process",
            "description": "Процесс запущен с EUID=0 или административным токеном",
        },
    },
    "known_malicious_process": {
        "class": EventClass.A,
        "title": "Запуск известного вредоносного процесса",
        "payload": {
            "category": "malware",
            "description": "Имя процесса совпало со списком известных вредоносных",
        },
    },
    "firewall_rule_changed": {
        "class": EventClass.A,
        "title": "Изменение правил межсетевого экрана",
        "payload": {
            "category": "network",
            "description": "Обнаружено изменение конфигурации firewall",
        },
    },
    "iptables_rule_changed": {
        "class": EventClass.A,
        "title": "Изменение правил iptables/nftables",
        "payload": {
            "category": "network",
            "description": "Обнаружено изменение правил iptables/nftables",
        },
    },
    "critical_security_error": {
        "class": EventClass.A,
        "title": "Критическая ошибка подсистемы безопасности",
        "payload": {
            "category": "system",
            "description": "Критическая ошибка ядра/подсистемы безопасности",
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
    "mdrj_service_start": {
        "class": EventClass.B,
        "title": "Запуск службы реестра MDRJ-DAG",
        "payload": {
            "category": "service_lifecycle",
            "description": "Узел эмитит это событие при штатном старте службы. Используется в паре с mdrj_service_stop для трассировки непрерывности работы.",
        },
    },
    "mdrj_service_stop": {
        "class": EventClass.B,
        "title": "Корректная остановка службы реестра MDRJ-DAG",
        "payload": {
            "category": "service_lifecycle",
            "description": "Узел эмитит это событие сам перед штатной остановкой. Отсутствие пары stop/start в реестре — улика принудительного прерывания сбора (атака УБИ.124 через kill -9).",
        },
    },
    "mdrj_service_killed": {
        "class": EventClass.A,
        "title": "Подозрительное прерывание службы реестра",
        "payload": {
            "category": "service_lifecycle",
            "description": "Эмитится при следующем старте, если в реестре найден mdrj_service_start без соответствующего mdrj_service_stop. Прямой признак того, что предыдущий процесс был убит (kill -9, OOM, аварийный crash), а не остановлен штатно.",
        },
    },
    "host_boot": {
        "class": EventClass.C,
        "title": "Загрузка операционной системы хоста",
        "payload": {
            "category": "system_lifecycle",
            "description": "Узел фиксирует загрузку операционной системы хоста сразу после своего старта. Каждая загрузка должна оставлять запись в реестре — её отсутствие в подозрительный период есть улика подмены журнала.",
        },
    },
    "host_reboot": {
        "class": EventClass.C,
        "title": "Перезагрузка операционной системы хоста",
        "payload": {
            "category": "system_lifecycle",
            "description": "Эмитится когда коллектор фиксирует резкое обнуление uptime — между двумя соседними poll boot_time изменился. На практике редкое событие: узел переживает перезагрузку только если процесс был перезапущен системным менеджером.",
        },
    },
}


def event_catalog() -> Mapping[str, Dict[str, object]]:
    """Return the configured catalog of known event kinds."""
    return EVENT_CATALOG


def is_known_event_kind(kind: str) -> bool:
    return kind in EVENT_CATALOG


def event_class_for(kind: str) -> EventClass:
    """Return MDRJ event class for a known event kind."""
    if kind not in EVENT_CATALOG:
        raise KeyError(f"unknown event_kind: {kind!r}")
    return EVENT_CATALOG[kind]["class"]  # type: ignore[return-value]


def catalog_title_for(kind: str) -> str:
    return str(EVENT_CATALOG[kind].get("title", kind))


def event_metadata(kind: str) -> Optional[Dict[str, object]]:
    """Return full metadata (rationale, linked_threats, added_by) для типа события.

    Возвращает None если тип неизвестен или каталог загружен из встроенного
    fallback без расширенных метаданных.
    """
    return _CATALOG_METADATA.get(kind)


def all_event_metadata() -> Dict[str, Dict[str, object]]:
    """Return метаданные для всех известных типов событий."""
    return dict(_CATALOG_METADATA)


# Применяем JSON-каталог при импорте, если он найден.
# Это даёт «горячую» точку правды: правка JSON + перезапуск узла = новый
# каталог, без правки Python-кода. Если JSON не найден или некорректен —
# остаётся встроенный EVENT_CATALOG из dict выше.
_json_catalog = _load_from_json()
if _json_catalog is not None:
    EVENT_CATALOG = _json_catalog
