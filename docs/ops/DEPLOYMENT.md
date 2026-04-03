# Deployment И Эксплуатационный Контур

## Что Известно Сейчас
В репозитории подтверждён только локальный и demo deploy-контур. Документированных production server, staging, CI/CD pipeline или внешних хостов в репозитории нет.

Это важно: наличие `Dockerfile` и `docker-compose.yaml` не означает, что production deployment уже определён.

## Текущие Способы Запуска

### Локальный Один Узел
- Команда:
  - `python -m mdrj.cli node --config configs/node.example.yaml`
- Конфиг:
  - `configs/node.example.yaml`
- Локальное хранилище по умолчанию:
  - `data/node1.db`

### Demo-Узел
- Команда:
  - `python -m mdrj.cli node --config configs/node.demo.yaml`
- Конфиг:
  - `configs/node.demo.yaml`
- Локальное хранилище:
  - `data/demo-node.db`

### Docker Compose Кластер
- Файлы:
  - `Dockerfile`
  - `docker-compose.yaml`
  - `docker/configs/node1.yaml`
  - `docker/configs/node2.yaml`
  - `docker/configs/node3.yaml`
- Команда запуска:
  - `docker compose up --build -d node1 node2 node3`
- Порты:
  - `localhost:9101 -> node1:9001`
  - `localhost:9102 -> node2:9002`
  - `localhost:9103 -> node3:9003`
- Данные:
  - отдельные Docker volumes `node1-data`, `node2-data`, `node3-data`
- Healthcheck:
  - `GET /status` внутри контейнера

### Demo-Сценарий Baseline
- Профиль Compose:
  - `demo-baseline`
- Команда:
  - `docker compose --profile demo-baseline up demo-baseline`
- Скрипт:
  - `docker/scripts/demo_baseline.sh`

## Конфигурация И Секреты
- Основная конфигурация узла задаётся YAML-файлом.
- В репозитории присутствуют demo-значения `security.hmac_key`.
- Эти значения нельзя считать production-секретами.
- Если появится production deploy, реальные секреты должны храниться вне git и быть привязаны к конкретному зафиксированному release/commit.

## Storage И Данные
- Каждый узел владеет отдельным SQLite-файлом.
- Для Docker Compose данные вынесены в отдельные volumes.
- Так как migration framework пока отсутствует, любые изменения схемы требуют особой осторожности:
  - backup перед релизом;
  - документированный rollback;
  - отдельный task spec.

## Production Deploy: Правила И Ограничения
- Production deploy разрешён только от зафиксированного commit SHA.
- Нельзя деплоить из незакоммиченного рабочего дерева.
- Нельзя считать production-контур существующим, если не зафиксированы:
  - host или группа host;
  - способ доставки артефакта;
  - способ хранения секретов;
  - способ backup/rollback;
  - post-deploy verification.

Пока эти данные не задокументированы, production deploy для проекта считается неописанным.

## Минимум Для Будущего Production Runbook
Когда появится реальный production-контур, в этом документе нужно явно добавить:
- список environments;
- хосты или orchestration platform;
- путь к конфигам и секретам;
- release artifact;
- пошаговый deploy;
- post-deploy verification;
- rollback до предыдущего commit;
- владельца операционного процесса.

## Зафиксированное Следующее Направление
- Следующий проектный production-контур для реальной среды предполагает один самодостаточный контейнер на один Linux-узел.
- Такой контейнер должен включать в себя:
  - ingestion-агент;
  - runtime MDRJ-DAG;
  - локальную SQLite-базу;
  - HTTP API и встроенный UI.
- Контейнер должен читать системные источники хоста (`journald`, `auth.log`, `sudo`) и обрабатывать их внутри узла, без обязательного второго sidecar-контейнера.
- На текущий момент это только проектное решение, а не уже реализованный deploy-контур.
- До реализации такого контейнера production deployment всё ещё считается неописанным.

## Обязательное Чтение Перед Infra/Deploy Задачами
Перед созданием задачи или реализацией, затрагивающей deploy/infra/production, обязательно перечитывать:
- `docs/WORKFLOW.md`
- `docs/constitution.md`
- `docs/architecture/architecture.md`
- `docs/devplan/devplan.md`
- `docs/ops/DEPLOYMENT.md`
- релевантные task specs
