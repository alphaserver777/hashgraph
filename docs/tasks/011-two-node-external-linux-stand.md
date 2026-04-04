# Task: Развернуть Внешний Испытательный Стенд На Двух Linux-Узлах

## Проверка Контекста Перед Работой
- [x] Перечитан `docs/WORKFLOW.md`
- [x] Перечитан `docs/constitution.md`
- [x] Перечитан `docs/architecture/architecture.md`
- [x] Перечитан `docs/architecture/invariants.md`
- [x] Перечитан `docs/devplan/devplan.md`
- [x] Перечитаны релевантные `docs/tasks/*.md`
- [x] Перечитан `docs/ops/DEPLOYMENT.md`

## Status
`in-progress`

## Контекст
После появления универсального `linux-node` и первого вертикального среза Linux ingestion следующий практический шаг — вынести этот контур на два внешних Linux-сервера и проверить реальную репликацию между публичными IP. Для стенда уже известны два сервера: `Germany` (`64.188.64.23`) и `Zomro` (`46.21.250.147`).

## Цель
Поднять по одному узлу `linux-node` на двух внешних Linux-хостах, проверить внешний runtime, репликацию и ingestion первого production-oriented сигнала без введения новых архитектурных сущностей.

## Scope
- Подготовить и задокументировать env-параметры для двух внешних узлов.
- Развернуть один и тот же `linux-node` на `Germany` и `Zomro`.
- Проверить `/status`, `/peers`, `/viz` и распространение `admin_ssh_login_success` между узлами.
- Зафиксировать фактический deploy-контур и выводы в документации.

## Ограничения
- Не объявлять стенд production-ready.
- Не вводить TLS, registry service, seed-discovery или новый orchestration layer в рамках этой задачи.
- Не оставлять UI/API открытыми на весь интернет без firewall-ограничений.
- Не смешивать задачу с расширением ingestion beyond `admin_ssh_login_success`.

## Текущее состояние
- Есть один универсальный `linux-node`.
- Есть один реальный ingestion-сигнал `admin_ssh_login_success`.
- Есть универсальный конфиг `docker/configs/linux-node.yaml`.
- Есть только локальная верификация и bootstrap-контур.

## Предлагаемое изменение
- Использовать один и тот же compose-сервис `linux-node` на двух серверах.
- Настроить `Germany` и `Zomro` только через env-переменные.
- Запускать контейнеры от зафиксированного commit SHA.
- Проверить внешний обмен между двумя публичными IP и реальный ingestion из `auth.log`.

## Затронутые области
- Документация:
  - эта task spec
  - `docs/ops/DEPLOYMENT.md`
  - `docs/architecture/architecture.md`
- Deploy / Infra:
  - `docker-compose.yaml`
  - `docker/configs/linux-node.yaml`

## Acceptance Criteria
- [x] Для двух внешних узлов описан единый deploy-контур.
- [x] Зафиксированы env-наборы для `Germany` и `Zomro`.
- [ ] Оба узла подняты от зафиксированного commit.
- [ ] Узлы видят друг друга как peers.
- [ ] Реальный `admin_ssh_login_success` появляется на исходном узле и реплицируется на второй.
- [ ] Документация отражает итоговое фактическое состояние стенда.

## Verification
- [x] Проверены docs на соответствие универсальному `linux-node`.
- [ ] `docker compose --profile linux-node up --build -d linux-node` на `Germany`
- [ ] `docker compose --profile linux-node up --build -d linux-node` на `Zomro`
- [ ] `curl /status` и `curl /peers` на обоих узлах
- [ ] Ручная браузерная проверка `/viz` на обоих узлах
- [ ] Ручной тест реального успешного административного SSH-входа

## Rollback / Safety
Откат должен позволять остановить и удалить стендовые контейнеры без влияния на локальный demo-контур. При необходимости стендовый узел должен очищаться командой `docker compose --profile linux-node down -v`.

## Заметки
- Пока нет TLS и mutual auth, этот контур должен считаться внешним испытательным стендом, а не production.
- Стенд валиден только при явном firewall-ограничении доступа к портам узлов.
