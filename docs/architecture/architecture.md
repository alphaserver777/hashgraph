# Текущее Состояние Архитектуры

## Назначение Репозитория
`hashgraph` содержит Python-прототип MDRJ-DAG: минимально достаточный распределённый журнал событий безопасности. Узлы локально создают события, сохраняют их в SQLite, распространяют через leaderless gossip и рассчитывают детерминированный порядок на своей стороне.

Это не production-ready платформа. Это рабочий прототип с локальным и demo-контуром запуска, который уже достаточно сложен, чтобы требовать фиксированной документационной дисциплины.

## Реальные Логические Области Системы

### 1. Runtime узла
- `mdrj/node.py` является центральной оркестрацией узла.
- Отвечает за bootstrap, жизненный цикл, эмиссию событий, ingest gossip batch, запуск HTTP API, gossip loop, метрики и взаимодействие со storage.
- Здесь сходятся почти все ключевые policy-решения проекта.

### 2. Хранение
- `mdrj/storage.py` реализует локальное долговременное хранение на SQLite.
- Таблицы:
  - `events`
  - `edges`
  - `envelopes`
  - `peers`
  - `consensus_state`
  - `incidents`
- Схема создаётся в коде при инициализации.
- WAL включается сразу.
- Отдельного migration layer сейчас нет.

### 3. Доменная логика репликации и упорядочивания
- `mdrj/vectorclock.py` отвечает за причинный контекст.
- `mdrj/consensus.py` рассчитывает `round`, `round_received`, `is_witness`, `is_famous_witness`, `fame_decided`, `fame_decision_round`, `fame_decision_kind`, `fame_needs_coin`, `fame_coin_used`, `fame_coin_round`, `fame_vote_round`, `fame_vote_yes`, `fame_vote_no` и `consensus_ts`.
- `mdrj/prioritization.py` управляет relay/pick policy для gossip batch.
- `mdrj/gossip.py` выполняет периодическую отправку envelope-пакетов пирам.
- `mdrj/metrics.py` собирает runtime-метрики состояния и сходимости.
- Этот слой уже даёт детерминированный порядок первого hashgraph-подобного этапа: через `rounds`, `witness`, preparatory `famous witness`, `round_received`, membership snapshot и `consensus_ts` по сетевому наблюдению. Но он ещё не равен полноценному hashgraph-consensus в смысле Hedera: в проекте пока нет full famous witness voting и full `virtual voting`.

### 4. Контракты и интерфейсы
- `mdrj/api.py` публикует HTTP JSON API.
- `mdrj/cli.py` даёт основной операционный интерфейс для запуска узла, просмотра статуса, DAG и метрик, отправки событий и регистрации пиров.
- В `mdrj/api.py` также встроена браузерная demo-визуализация `/viz` и сценарии имитации событий.

### 5. Конфигурация
- `mdrj/config.py` преобразует YAML-конфиги в dataclass-структуры.
- Основные конфиги:
  - `configs/node.example.yaml`
  - `configs/node.demo.yaml`
  - `docker/configs/node1.yaml`
  - `docker/configs/node2.yaml`
  - `docker/configs/node3.yaml`
  - `docker/configs/linux-node.yaml`

### 6. Документы как источники правды
- `docs/event-classification.md` фиксирует policy классификации известных событий по классам `A/B/C`.
- `mdrj/event_catalog.py` является runtime-зеркалом этой policy.
- `mdrj/simulation.py` использует только demo-подмножество известных событий, а не весь runtime-каталог.
- Рабочая проектная документация ведётся только в `docs/`.
- Минимальный Linux-контур первого вертикального среза уже реализован: самодостаточный контейнер узла может читать один файл `auth.log` и публиковать `admin_ssh_login_success` во внутренний runtime.

## Точки Входа
- Локальный запуск узла:
  - `python -m mdrj.cli node --config <yaml>`
- CLI для работы с API:
  - `emit`
  - `status`
  - `dag`
  - `metrics`
  - `metrics-watch`
  - `peers add`
  - `peers list`
- Docker Compose demo-кластер:
  - `docker compose up --build -d node1 node2 node3`
- Тестовый вход:
  - `pytest`

## Хранение и доменные источники правды
- Истина о существующих событиях и связях DAG находится в SQLite конкретного узла.
- Истина об активном consensus membership snapshot и его epoch тоже находится в SQLite конкретного узла.
- Истина о локальных operator-инцидентах на выбранном узле тоже находится в SQLite конкретного узла.
- Истина о классификации известных event kinds находится в `docs/event-classification.md`.
- Истина о текущих config fields находится в YAML-конфигах и `mdrj/config.py`.
- Истина о runtime semantics `consensus_ts`, gossip и эмиссии находится в коде, а не в README.

## Фактическое Поведение На Сегодня
- Узел работает как отдельный Python-процесс с собственным SQLite-файлом.
- При bootstrap узел теперь создаёт не один пустой anchor, а набор genesis identity-anchor записей: для самого себя и для заранее известных по конфигурации участников.
- В Linux-режиме тот же узел может дополнительно запускать встроенный ingestion-loop, который читает `auth.log`-подобный источник, отслеживает offset в state-файле и создаёт production-oriented событие `admin_ssh_login_success`.
- При локальной эмиссии событие привязывается максимум к двум родителям: локальный self-parent, один недавний remote event, затем anchors как fallback.
- События хранятся как вершины DAG, а edges поддерживаются отдельно.
- Envelope содержит событие и `path_meta`, которое используется при расчёте `consensus_ts`.
- Consensus pipeline теперь работает через frozen membership snapshot: live peer-registry не влияет на majority и порядок, пока оператор явно не выполнит `reconfigure consensus membership`.
- Событие теперь хранит явные `creator`, `self_parent_id`, `other_parent_id`, `round`, `round_received`, `is_witness`, `is_famous_witness`, `fame_decided`, `fame_decision_round`, `fame_decision_kind`, `fame_needs_coin`, `fame_coin_used`, `fame_coin_round`, `fame_vote_round`, `fame_vote_yes` и `fame_vote_no`.
- Текущий `consensus_ts` уже не считается по старой локальной формуле. Он вычисляется после `round_received` как медиана наблюдений membership snapshot из `path_meta`.
- `/status` теперь показывает не только epoch и fingerprint active snapshot, но и явный статус `ok/pending/mismatch` по сверке consensus snapshots с пирами.
- Этот алгоритм нужно считать preparatory hashgraph-like ordering, а не production-эквивалентом Hedera fairness/ordering. Fame witness уже имеет явный decision state и vote provenance, поздние fame-rounds больше не fallback-ятся к прямой видимости target witness, internal fame pipeline уже строит round-by-round vote history, итог fame разрешается отдельным formal decision layer, `round_received` больше не использует partially decided fame rounds, unresolved fame сначала помечается как `fame_needs_coin`, а затем при необходимости закрывается deterministic coin surrogate. Новый `fame_decision_kind` явно различает обычное vote-решение, pending-состояние и surrogate coin-решение, чтобы следующий protocol-step мог заменить surrogate без поломки persisted state. Но full famous witness voting и full `virtual voting` ещё не реализованы.
- Genesis-записи теперь несут ещё и bootstrap identity-контекст: `subject_node_id`, адреса и доступные локально метаданные узла.
- Класс `A` обязательно gossip-реплицируется.
- По README и текущему коду класс `B` сейчас также активно проталкивается в relay-план.
- Класс `C` служебный/best-effort и важен для замыкания DAG.
- `/viz` встроен прямо в backend-код и обслуживается тем же aiohttp приложением.
- Incident-workbench в `/viz` теперь включается по локальной роли узла `responder`, которая хранится в SQLite peer-registry. Это не распределённая подсистема и не общий кластерный source of truth.
- Peer-registry теперь тоже имеет локальное SQLite-состояние узла: оператор может видеть, добавлять, исключать и удалять участников сети из веб-панели, а также назначать локальные роли `node/responder`. При этом такое решение остаётся локальной operator-моделью конкретного узла, а не кластерным консенсусом по составу сети или ролям.
- Consensus membership теперь отделён от peer-registry: peer-registry остаётся live operator-state, а consensus использует только зафиксированный snapshot текущей epoch.
- Linux ingestion пока не является полным production ingestion-layer: поддержан только один реальный сигнал `admin_ssh_login_success` через file-based источник, а не весь каталог `journald/auth.log/sudo`.

## Размещение И Запуск
- В репозитории есть подтверждённый deploy-контур только для локального/demo использования:
  - один узел на локальной машине;
  - локальный multi-process сценарий через `scripts/`;
  - Docker Compose с тремя контейнерами `node1/node2/node3`.
- Дополнительно есть отдельный Docker Compose профиль `linux-node` с универсальным сервисом `linux-node` для первого вертикального среза Linux ingestion. Это технический bootstrap-контур, а не подтверждённый production deploy.
- В Compose:
  - внешние порты `9101`, `9102`, `9103`;
  - внутренние сервисные порты `9001`, `9002`, `9003`;
  - данные узлов лежат в отдельных Docker volumes.
- Подтверждённых production server, CI/CD pipeline, staging environment, reverse proxy, TLS termination или managed database в репозитории не зафиксировано.
- Любые утверждения о production placement без отдельной фиксации надо считать предположением.

## Текущие Ограничения И Проблемы
- Нет framework для schema migrations.
- Нет формализованного reference по API contracts и storage contracts.
- Встроенный UI в `mdrj/api.py` увеличивает размер и связанность backend-модуля.
- Compose и demo-конфиги не равны production-hardening.
- HMAC-конфигурация есть, но полноценной production-модели доверия, TLS и mutual auth нет.
- В репозитории остаются архивные артефакты в `.skaro/`; рабочей точкой правды для документации считается только `docs/`.
- Первый реальный ingestion уже появился, но покрывает только один тип сигнала и один file-based источник; до полноценного Linux ingestion-layer проекту ещё далеко.
- Состав сети пока не обнаруживается автоматически: operator-managed peer-registry улучшает управление узлами, но не заменяет будущий seed/discovery слой.
- Первый этап Hashgraph-подобного порядка уже реализован, а следующий preparatory fame-layer тоже введён. До полной модели ещё нужны отдельные шаги: full famous witness voting, `virtual voting`, более строгий `round_received` и диагностика mismatch membership snapshots между узлами.

## Целевое Направление Развития
- Вести все изменения через task specs в `docs/tasks/`.
- Формализовать protocol/storage contracts до серьёзных изменений в схеме и API.
- Явно отделить demo-поведение от поддерживаемого ядра.
- Держать архитектурные документы синхронными с фактическим кодом, а не с намерениями.
- Расширить уже появившийся self-contained Linux-режим от одного сигнала `admin_ssh_login_success` к минимальному рабочему набору событий доступа и привилегий.

## Что Не Нужно Путать С Архитектурой
- README полезен как вводный документ, но не заменяет архитектурные документы в `docs/architecture/`.
- План развития описывается в `docs/devplan/devplan.md`, а не здесь.
- Task specs описывают изменение, а не всю систему целиком.
