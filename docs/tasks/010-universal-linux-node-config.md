# Task: Перевести Linux-Узел На Один Универсальный Конфиг И Compose-Контур

## Проверка Контекста Перед Работой
- [x] Перечитан `docs/WORKFLOW.md`
- [x] Перечитан `docs/constitution.md`
- [x] Перечитан `docs/architecture/architecture.md`
- [x] Перечитан `docs/architecture/invariants.md`
- [x] Перечитан `docs/devplan/devplan.md`
- [x] Перечитаны релевантные `docs/tasks/*.md`
- [x] Перечитаны релевантные ADR, если они есть
- [x] Перечитан `docs/ops/DEPLOYMENT.md`, если задача затрагивает production/deploy/infra

## Status
`in-progress`

## Контекст
После появления Linux bootstrap-узла стало ясно, что дублирование конфигов `linux-node1`, `linux-node2` плохо масштабируется. Для реального внешнего стенда и дальнейшей эксплуатации нужен один универсальный конфиг узла и один universal compose-сервис, которые различаются только переменными окружения конкретного сервера.

## Цель
Сделать deploy Linux-узла воспроизводимым через один YAML-конфиг и один compose-контур, чтобы количество узлов сети не требовало линейного роста числа почти одинаковых файлов.

## Scope
- Добавить поддержку environment interpolation в config-loader.
- Подготовить один универсальный Linux-конфиг узла.
- Подготовить один универсальный compose-сервис Linux-узла.
- Задокументировать набор обязательных env-переменных.

## Ограничения
- Не ломать текущий demo-кластер `node1/node2/node3`.
- Не вводить полноценный orchestration layer.
- Не смешивать задачу с TLS, discovery или CI/CD.

## Текущее состояние
- Исторически Linux bootstrap-режим использовал отдельный файл `docker/configs/linux-node1.yaml`.
- Для второго внешнего узла пришлось бы создавать почти такой же файл.
- Config-loader не поддерживает подстановку env-переменных.

## Предлагаемое изменение
- В `mdrj/config.py` поддержать `${VAR}` и `${VAR:-default}` в YAML-строках.
- Сделать один файл `docker/configs/linux-node.yaml`, где различия между серверами задаются через env.
- Сделать один compose-сервис `linux-node`.
- Для списка пиров поддержать строку через запятую в env-переменной.

## Затронутые области
- Код:
  - `mdrj/config.py`
- Документация:
  - эта task spec
  - `docs/ops/DEPLOYMENT.md`
  - `README.md`
- Deploy / Infra:
  - `docker-compose.yaml`
  - `docker/configs/linux-node.yaml`

## Acceptance Criteria
- [x] Есть один универсальный Linux-конфиг узла.
- [x] Есть один универсальный compose-сервис Linux-узла.
- [x] Конфиг загружается через env-переменные.
- [x] Список пиров можно задать без отдельного YAML-файла на каждый узел.
- [x] Demo-кластер не сломан.

## Verification
- [x] `python -m py_compile mdrj/config.py`
- [x] `docker compose --profile linux-node config --services`
- [ ] Ручной запуск одного универсального Linux-узла с разными env на разных серверах

## Rollback / Safety
Откат должен возвращать старый file-per-node режим без изменения runtime-семантики узла. Demo-контур должен оставаться рабочим даже при полном revert этой задачи.

## Заметки
- Эта задача не исключает наличие локальных example env-файлов, но source of truth для формы конфига остаётся одним.
- Следующий шаг после неё — реальный rollout на `Germany` и `Zomro`.
