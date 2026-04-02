# Task: Формализовать API И Storage Contracts

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
`planned`

## Контекст
В репозитории уже есть рабочие CLI/API/storage-потоки, но их contracts пока распределены между кодом, README и тестами. При этом схема SQLite создаётся напрямую в `mdrj/storage.py`, а HTTP API живёт в `mdrj/api.py` без отдельного reference layer.

Для проекта, который дальше планируется развивать через LLM, это ближайший практический риск: следующая задача по storage, consensus, API или deploy может начать менять поведение без явного contract baseline.

## Цель
Создать явные и поддерживаемые reference-документы для:
- HTTP API contracts;
- storage schema и semantics;
- правил изменения schema/API без неявных breaking changes.

## Scope
- Добавить отдельные документы по API contracts и storage contracts.
- Зафиксировать текущие endpoint, request/response semantics и ограничения.
- Зафиксировать текущую SQLite schema, смысл таблиц и риски schema evolution.
- Уточнить, какие части являются demo-only, а какие считаются поддерживаемым ядром.

## Ограничения
- Не менять продуктовый код в рамках этой задачи, если это не требуется для исправления явного рассинхрона документации.
- Не делать big bang refactor API или storage.
- Не вводить migration framework в этой задаче.
- Не объявлять неподтверждённый production-контур существующим.

## Текущее состояние
- `mdrj/api.py` содержит HTTP API и встроенную визуализацию.
- `mdrj/storage.py` сам создаёт таблицы `events`, `edges`, `envelopes`, `peers`.
- README частично описывает endpoint и storage behavior, но не является достаточным contract document.
- Отдельного документа с правилами schema change и storage rollback пока нет, кроме общих ограничений в новых `docs/`.

## Предлагаемое изменение
- Создать в `docs/` отдельные practically useful документы, которые описывают текущий API и storage как reference.
- Явно связать эти документы с `docs/constitution.md`, `docs/architecture/architecture.md` и task workflow.
- Зафиксировать, как будущие изменения API и schema должны проходить через task specs, verification и rollback planning.

## Затронутые области
- Код:
  без планируемых изменений
- Тесты:
  возможна только сверка существующих тестов с документацией
- Документация:
  новые reference-документы в `docs/`
- Deploy / Infra:
  только документирование ограничений, если они влияют на API или storage

## Acceptance Criteria
- [ ] В `docs/` есть отдельный документ по текущим API contracts.
- [ ] В `docs/` есть отдельный документ по текущим storage contracts и schema semantics.
- [ ] В документах явно указано, какие части относятся к demo/runtime, а какие являются contract surface.
- [ ] `docs/architecture/architecture.md` и новые reference-документы не противоречат текущему коду.
- [ ] Для будущих schema/API changes зафиксирован ожидаемый процесс через task spec, verification и rollback.

## Verification
- [ ] Сверить endpoint и payload с `mdrj/api.py` и `mdrj/cli.py`.
- [ ] Сверить storage schema с `mdrj/storage.py`.
- [ ] Сверить ключевые semantics с существующими тестами и README.
- [ ] Проверить, что новые документы ссылаются на текущие source of truth, а не дублируют их без необходимости.

## Rollback / Safety
Изменения документационные. Если документы окажутся неточными, rollback делается обычным git revert на commit с документацией. Нельзя использовать эти документы как основание для изменения кода без отдельной task spec.

## Заметки
- Эта задача выглядит ближайшим следующим шагом, потому что снижает риск почти для всех последующих изменений.
- Если в ходе выполнения обнаружатся реальные контрактные расхождения между кодом и README, их нужно фиксировать явно, а не сглаживать формулировками.
