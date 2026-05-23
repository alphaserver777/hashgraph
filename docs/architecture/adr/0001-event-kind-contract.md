# ADR-0001: Явный event_kind как контракт эмиссии события

## Статус
Принято (этап 0 прототипа диссертационной работы по tamper-proof журналированию).

## Контекст
До этого решения `POST /event/emit` принимал произвольную пару `{cls, payload}`. Класс события (`A/B/C`) задавал клиент — то есть любой код, эмитирующий событие, сам решал критичность. `mdrj/event_catalog.py` использовался только в demo-симуляции `/viz/simulate`, не в продакшен-приёмке.

Это создавало две проблемы:
- Внешний коллектор мог пометить любое событие любым классом — нет дисциплины классификации.
- `docs/event-classification.md` (source of truth по policy A/B/C) не имел технического принуждения. Изменение классификации в документе не отражалось в коде эмиссии.

Прототип расширяется до полноценного коллектора кросс-платформенных событий ИБ (Linux + Windows). Без жёсткого контракта `event_kind` мы не сможем гарантировать одинаковую классификацию одного и того же типа события на разных хостах, что ломает аналитику в распределённом реестре.

## Решение
Введён обязательный (по новому пути) идентификатор типа события `event_kind`, валидируемый по `mdrj/event_catalog.py`:

- `POST /event/emit` теперь принимает оба формата:
  - **Новый рекомендуемый:** `{event_kind, payload}`. Класс `cls` выводится из `EVENT_CATALOG[event_kind]["class"]`; `event_kind` дописывается в `payload`. Неизвестный `event_kind` отвергается с HTTP 400.
  - **Legacy:** `{cls, payload}` — продолжает работать ради совместимости с demo-симуляцией и тестами. На этом пути `event_kind` не валидируется.
- `event_catalog.py` расширен полным списком event kinds, требуемых задачей: `admin_login_failure`, `failed_login_burst`, `remote_login_rdp`, `critical_file_modified`, `windows_registry_modified`, `privileged_process_started`, `known_malicious_process`, `firewall_rule_changed`, `iptables_rule_changed`, `critical_security_error`.
- `docs/event-classification.md` обновлён под новые kinds — он остаётся source of truth, runtime-каталог должен следовать за ним.
- Helper-функции `is_known_event_kind(kind)`, `event_class_for(kind)` (с явным `KeyError` для неизвестных), `catalog_title_for(kind)`.

Решение **не трогает** dataclass `Event` — `event_kind` живёт в payload. Это важно, потому что схема `Event` сейчас активно изменяется в WIP-ветке по task 014 (hashgraph consensus alignment). Изоляция через payload не создаёт конфликтов слияния.

## Последствия
**Положительные:**
- Классификация события становится воспроизводимой между хостами Linux и Windows.
- Изменение классификации делается в одном месте — `event_catalog.py` + `docs/event-classification.md`, а не в коде каждого коллектора.
- Открыта дорога к этапу 1 (универсальный модуль `mdrj/collectors/*`): коллекторы шлют `event_kind`, runtime сам выводит класс.

**Отрицательные / ограничения:**
- Legacy-путь `{cls, payload}` оставлен включённым, чтобы не ломать demo-симуляцию `/viz/simulate` и существующие тесты. Его рекомендуется удалить в этапе 3 (ротация реестра), когда вокруг каталога устаканится policy.
- Валидация `event_kind` живёт в HTTP-handler, а не в самом `Event.create`. Если в будущем появятся другие точки эмиссии (внутри runtime), валидацию надо будет дублировать или вынести в `Node.emit_event`.

## См. также
- [docs/event-classification.md](../../event-classification.md) — source of truth по A/B/C policy.
- [mdrj/event_catalog.py](../../../mdrj/event_catalog.py) — runtime-зеркало policy.
- [ADR-0002](0002-hmac-api-auth.md) — аутентификация state-changing endpoints (необходима для безопасной приёмки `event_kind` от удалённых коллекторов).
