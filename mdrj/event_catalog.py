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
