# ADR-0003: Пакет `mdrj/collectors/` для кросс-платформенного сбора событий ИБ

## Статус
Принято (этап 1 прототипа диссертационной работы).

## Контекст
До этого решения в репозитории был один Linux ingest-loop — `mdrj/linux_ingest.py:LinuxAuthLogIngestor`, который читал только `auth.log` и распознавал один сигнал `admin_ssh_login_success`. Этот модуль вызывался напрямую из `Node._linux_ingest_loop` с жёстко прибитым `EventClass.A` и логикой, специфичной для одного источника.

Задача диссертационной работы требует расширения до **полного списка критичных событий ИБ** ([docs/event-classification.md](../../event-classification.md)) с **кросс-платформенной поддержкой** (Linux + Windows). Прибавление каждого нового источника как отдельного метода в `node.py` или нового файла в корне `mdrj/` приведёт к расползанию архитектуры: одинаковая логика (poll-loop, state-tracking, error-handling, event-emission) будет копироваться, и контракт между источником и узлом не будет формализован.

## Решение
Введён отдельный пакет `mdrj/collectors/` с базовым классом и набором конкретных коллекторов:

- **`base.py`** — `BaseCollector` определяет минимальный контракт: `poll() -> List[CollectedEvent]`, `poll_interval_sec`, `name`, `status` (для отображения в `/status`/`/metrics`). `CollectedEvent` — нормализованная пара `(event_kind, payload)`.
- **`linux_auth.py`** — тонкая обёртка над существующим `LinuxAuthLogIngestor`. Сохраняет совместимость с `tests/test_linux_ingest.py`, не меняет парсинг.
- **`linux_journald.py`** — детектирует `admin_login_failure` и `failed_login_burst` по `journalctl --output=json`. Sliding-window in-memory для burst-детекции, дросселирование burst-эмиссии. Если `journalctl` недоступен (Docker без systemd) — коллектор гасит сам себя через `status.enabled = False`.
- **`linux_audit.py`** — простой mtime/sha256-watcher критических конфигов (`/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config` и т.д.). На первый poll baseline без событий, на последующих — `critical_file_modified` при расхождении. Не требует auditd — это минимальный достаточный механизм для прототипа.
- **`linux_firewall.py`** — периодически вызывает `iptables-save` (или `nft list ruleset`) и считает SHA256 от вывода. При изменении — `iptables_rule_changed`. Black-box differ: не парсит правила, только детектирует мутацию ruleset.
- **`linux_proc.py`** — сканирует `/proc/*` на новые PID-ы между поллами. Если basename исполняемого файла или `comm` совпадает с blocklist (xmrig, minerd, kdevtmpfsi…) → `known_malicious_process`. Если UID нового процесса в `privileged_uids` (по умолчанию `[0]`) → `privileged_process_started`. Идемпотентность через множество seen_pids.

Оркестрация в `mdrj/node.py`:
- `_build_collectors()` создаёт только включённые в конфиге коллекторы.
- `_start_collectors()` запускает для каждого свой `asyncio.Task`, который циклически зовёт `poll()` через `asyncio.to_thread` (poll синхронный — он читает файлы/процессы), затем эмитит события через `Node.emit_event(cls, payload)`, где `cls` выводится из `event_catalog`.
- `_run_collector_loop` логирует `unknown event_kind` и пропускает — коллектор не может протолкнуть событие, которого нет в каталоге.
- Существующий `_linux_ingest_loop` оставлен **нетронутым** ради обратной совместимости с конфигами, использующими секцию `linux_ingest:`.

Конфигурация:
- В `mdrj/config.py` добавлена секция `collectors:` с подсекциями `journald`, `audit`, `firewall`, `proc`. По умолчанию все коллекторы выключены (`enabled: false`) — узел не запускает их пока оператор явно не включит. Это сохраняет backward-compat с существующими `node.example.yaml`, `node.demo.yaml`, `docker/configs/*.yaml`.

Циклический импорт между `mdrj.config` и `mdrj.collectors`:
- `mdrj.config` импортирует `JournaldCollectorConfig` и т.д. из пакета.
- `mdrj.collectors.linux_auth` через `mdrj.linux_ingest` импортирует `LinuxIngestConfig` из `mdrj.config`.
- Чтобы разорвать цикл: `LinuxAuthCollector` **не** реэкспортируется в `mdrj/collectors/__init__.py`. Импортируется напрямую: `from mdrj.collectors.linux_auth import LinuxAuthCollector`. Type hint на `LinuxIngestConfig` дан через `TYPE_CHECKING`.

## Последствия
**Положительные:**
- Один контракт для всех источников; добавление нового сводится к новому файлу в `mdrj/collectors/` плюс enable-флагу в конфиге.
- Логика burst-detection, mtime-diff, digest-diff и process-snapshot покрыта unit-тестами (`tests/test_collectors.py`, 9 тестов).
- Каждый коллектор имеет `CollectorStatus`, что готовит почву для отображения health в Web UI (этап 5) и в метриках (этап 2).
- Локальная фильтрация уже работает через `event_catalog`: коллектор не может пометить событие неверным классом, потому что класс берётся из каталога, а не от коллектора.
- Класс `C` события (heartbeat-подобные) не gossip-ятся (логика уже в `prioritization`), значит коллекторы могут эмитить «болтливые» сигналы без раздувания распределённого реестра — это и есть «фильтр перед записью».

**Отрицательные / ограничения:**
- **Дублирование auth-source.** Если оператор включит и `linux_ingest.enabled` (старый путь), и `collectors.journald.enabled` (новый путь) с теми же SSH-логами — события будут эмититься дважды. Это TODO для этапа 2: унифицировать в один контур, постепенно вывести `linux_ingest` из эксплуатации.
- **Synchronous poll через `asyncio.to_thread`.** Это нормально для poll-интервалов ≥1 секунды, но при тысячах процессов в `/proc` каждый proc-poll может задержать общий thread pool. Для production нужно переходить на async-IO или дробить scan.
- **Auditd не реализован.** `linux_audit.py` — это mtime/sha256-watcher, не настоящий auditd. Он пропускает события «открытие файла на чтение», «попытка изменения без успеха», и т.п. Для полноценного auditd-интеграции нужен этап 2.
- **`/proc/PID/exe` через symlink.** `os.readlink` возвращает текущую цель симлинка. Если процесс уже завершился между обнаружением и чтением — `OSError`, который мы молча обрабатываем. Это может пропустить short-lived malware.
- **Windows-коллекторов нет.** Будут в этапе 7.

## См. также
- [ADR-0001](0001-event-kind-contract.md) — контракт `event_kind`, без которого этот пакет не имел бы смысла.
- [docs/event-classification.md](../../event-classification.md) — source of truth по классификации.
- [docs/devplan/devplan.md](../../devplan/devplan.md) этап 2.4 «Построить минимальный production ingestion для Linux».
