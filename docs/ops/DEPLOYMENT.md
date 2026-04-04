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

### Docker Compose Linux Bootstrap
- Файлы:
  - `docker-compose.yaml`
  - `docker/configs/linux-node.yaml`
  - `docker/linux-fixtures/auth.log`
- Профиль:
  - `linux-node`
- Команда запуска:
  - `docker compose --profile linux-node up --build -d linux-node`
- Порты:
  - по умолчанию `localhost:9111 -> linux-node:9011`, но bind задаётся env-переменной
- Данные:
  - отдельный Docker volume `linux-node-data` по умолчанию, но имя тоже может задаваться env-переменной
- Источник первого сигнала:
  - read-only `auth.log`, путь задаётся env-переменной
- Назначение:
  - технический bootstrap для первого vertical slice Linux ingestion, а не production deploy
- Важный принцип:
  - используется один универсальный YAML-конфиг узла и один compose-сервис;
  - различия между серверами задаются через env-переменные (`NODE_ID`, `HOST_ID`, `LISTEN`, `PEERS`, пути и порты)

### Внешний Испытательный Стенд На Два Linux-Хоста
- Назначение:
  - проверить первый внешний контур репликации и ingestion на двух публично доступных Linux-серверах;
  - не считать этот контур production-ready до появления TLS, более сильной модели доверия и нормального release-процесса.
- Модель:
  - на каждом хосте запускается один контейнер `linux-node`;
  - каждый контейнер использует один и тот же `docker/configs/linux-node.yaml`;
  - различия задаются только env-переменными конкретного сервера.
- Подтверждённые внешние узлы стенда:
  - `Germany` (`64.188.64.23`)
  - `Zomro` (`46.21.250.147`)
- Минимальные требования:
  - установлен `docker` и `docker compose`;
  - доступен читаемый `auth.log` на хосте;
  - открыт только порт runtime узла для второго стендового сервера и для оператора;
  - доступ к UI/API не публикуется на весь интернет без firewall-ограничений.

#### Переменные Для Germany
```bash
NODE_ID=linux-node-germany
HOST_ID=germany-host
LISTEN=0.0.0.0:9011
LINUX_CONTAINER_PORT=9011
LINUX_PORT_BIND=9111
LINUX_CONTAINER_NAME=mdrj-linux-node-germany
LINUX_DATA_VOLUME=linux-node-germany-data
PEERS=46.21.250.147:9011
AUTH_LOG_BIND_PATH=/var/log/auth.log
```

#### Переменные Для Zomro
```bash
NODE_ID=linux-node-zomro
HOST_ID=zomro-host
LISTEN=0.0.0.0:9011
LINUX_CONTAINER_PORT=9011
LINUX_PORT_BIND=9111
LINUX_CONTAINER_NAME=mdrj-linux-node-zomro
LINUX_DATA_VOLUME=linux-node-zomro-data
PEERS=64.188.64.23:9011
AUTH_LOG_BIND_PATH=/var/log/auth.log
```

#### Порядок Развёртывания На Каждом Хосте
1. Развернуть зафиксированный commit нужной ветки репозитория.
2. Подставить env-переменные узла.
3. Запустить:
   - `docker compose --profile linux-node up --build -d linux-node`
4. Проверить:
   - `curl http://127.0.0.1:<port>/status`
   - `curl http://127.0.0.1:<port>/peers`
   - `http://<host>:<port>/viz`
5. На одном из серверов выполнить реальный успешный административный SSH-вход.
6. Убедиться, что `admin_ssh_login_success` появился на локальном узле и затем реплицировался на второй.

#### Ограничения И Риски Стенда
- Пока нет TLS и подтверждённой mutual auth-модели для внешней сети.
- Поэтому стенд нужно считать внешним испытательным, а не production.
- Сброс `docker compose down -v` удаляет локальную SQLite-базу и состояние ingestion на конкретном узле.
- Для reproducible rollout использовать только зафиксированный commit SHA.

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
- На текущий момент частично реализован только bootstrap-вариант: один узел умеет читать file-based `auth.log` и выделять `admin_ssh_login_success`.
- Это ещё не production deploy-контур и не доказательство готовности к реальному развёртыванию.
- До реализации такого контейнера production deployment всё ещё считается неописанным.

## Обязательное Чтение Перед Infra/Deploy Задачами
Перед созданием задачи или реализацией, затрагивающей deploy/infra/production, обязательно перечитывать:
- `docs/WORKFLOW.md`
- `docs/constitution.md`
- `docs/architecture/architecture.md`
- `docs/devplan/devplan.md`
- `docs/ops/DEPLOYMENT.md`
- релевантные task specs
