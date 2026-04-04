# Task: Добавить Genesis-Записи Идентичности Для Известных Узлов

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
Сейчас genesis в узле создаётся как служебный anchor с минимальным payload `{"anchor": 0, "node": ..., "genesis": true}`. Этого достаточно для замыкания DAG, но недостаточно для идентификации состава сети. Оператору и следующей логике трудно понять, какие узлы считались известными при bootstrap, как они были адресованы и какой локальный identity у текущего узла.

## Цель
Сделать genesis-записи не только техническими anchor-событиями, но и минимальными паспортами известных узлов, содержащими идентификационную информацию о текущем узле и заранее известных участниках.

## Scope
- Добавить отдельную задачу на identity-genesis.
- Расширить genesis payload для текущего узла.
- Генерировать genesis-запись для каждого известного узла из bootstrap-контекста.
- Сохранить их как anchors для дальнейшей эмиссии событий.
- Обновить документы и минимальные тесты.

## Ограничения
- Не строить в этой задаче полноценный discovery-протокол.
- Не утверждать, что информация о пирах подтверждена ими самими.
- Не вводить PKI, подписи узлов или взаимную аутентификацию.
- Не ломать текущий инвариант: genesis anchors должны появляться до обычной эмиссии.

## Текущее состояние
- Genesis создаётся один раз на узел.
- Payload genesis не содержит достаточной identity-информации.
- Список известных участников уже существует через config peers и peer-registry, но он не материализуется в DAG как bootstrap-состояние сети.

## Предлагаемое изменение
- Для текущего узла genesis должен содержать как минимум:
  - `subject_node_id`
  - `host_id`
  - `runtime_hostname`
  - `listen`
  - `listen_host`
  - `listen_port`
  - `identity_scope: self`
- Для заранее известных участников по config peers должен появиться отдельный genesis-anchor с минимально доступной локально информацией:
  - `subject_node_id`
  - `configured_peer_address`
  - `configured_peer_host`
  - `configured_peer_port`
  - `identity_scope: known_peer`
- Все такие записи должны оставаться `genesis: true` и участвовать как anchors.

## Затронутые области
- Код:
  - `mdrj/node.py`
- Тесты:
  - `tests/test_storage.py`
- Документация:
  - эта task spec
  - `docs/architecture/architecture.md`
  - `docs/architecture/invariants.md`

## Acceptance Criteria
- [x] Genesis содержит identity-поля текущего узла.
- [x] При bootstrap создаётся genesis-запись для каждого известного узла из конфигурации.
- [x] Такие записи остаются anchors для обычной эмиссии.
- [x] Реализация не ломает существующий bootstrap графа.
- [x] Документация отражает новую роль genesis как identity-anchor.

## Verification
- [x] `python -m py_compile mdrj/node.py`
- [x] Добавлен unit-smoke на bootstrap identity-genesis
- [ ] Ручная проверка в `/viz`, что genesis payload теперь содержит identity-информацию

## Rollback / Safety
Откат должен возвращать старый минимальный genesis без изменения формата обычных событий. Если новая форма genesis создаёт проблемы в визуализации или bootstrap, откат ограничивается `mdrj/node.py`, тестом и документами.

## Заметки
- Эта задача не доказывает истинность удалённого узла. Она только фиксирует bootstrap-представление о составе сети на конкретном узле.
- Следующий шаг может расширить это решение до self-announcement и подтверждения identity между узлами.
