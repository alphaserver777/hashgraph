# Task: Помечать Нерешённый Fame Как Требующий Coin Step

## Проверка Контекста Перед Работой
- [x] Перечитан `docs/WORKFLOW.md`
- [x] Перечитан `docs/constitution.md`
- [x] Перечитан `docs/architecture/architecture.md`
- [x] Перечитан `docs/architecture/invariants.md`
- [x] Перечитан `docs/devplan/devplan.md`
- [x] Перечитаны релевантные `docs/tasks/*.md`
- [ ] Перечитаны релевантные ADR, если они есть
- [ ] Перечитан `docs/ops/DEPLOYMENT.md`, если задача затрагивает production/deploy/infra

Без этой проверки нельзя ни писать новую задачу, ни начинать реализацию.

## Status
`completed`

## Контекст
После `021` fame decision уже вычисляется отдельным resolver поверх vote history, а после `022` partially decided fame rounds больше не участвуют в `round_received`. Но unresolved fame пока выглядел просто как `decided=False`. Для следующего hashgraph-подобного шага нужно уметь явно различать состояние “решение ещё не наступило, но обычные vote rounds уже исчерпали себя” и “мы всё ещё на раннем этапе голосования”.

## Цель
Ввести явный флаг `fame_needs_coin`, который будет отмечать unresolved fame cases, дошедшие до точки, где следующий этап уже должен использовать coin-step или более сложный voting rule-set.

## Scope
- Добавить `fame_needs_coin` в:
  - `Event`
  - `ConsensusState`
  - SQLite schema
  - runtime persistence
- Resolver должен ставить `fame_needs_coin=True`, если:
  - fame не решена;
  - уже есть как минимум два vote rounds history.
- Если есть только initial vote round, `fame_needs_coin=False`.

## Ограничения
- Не реализовывать сам coin round.
- Не менять `round_received`, storage contracts порядка и membership snapshot.
- Не делать UI/HTTP изменения под этот флаг в этой задаче.

## Текущее состояние
- Fame уже имеет:
  - decision state
  - vote trace
  - round-by-round history
  - formal decision resolver
- Но unresolved fame ещё не классифицировалась по степени готовности к следующему этапу voting.

## Предлагаемое изменение
- Ввести флаг `fame_needs_coin`.
- Persist-ить его вместе с остальными fame-полями.
- Проверить:
  - unresolved history с двумя rounds -> `needs_coin=True`
  - unresolved history только с initial vote round -> `needs_coin=False`

## Затронутые области
- Код:
  - `mdrj/models.py`
  - `mdrj/consensus.py`
  - `mdrj/storage.py`
  - `mdrj/node.py`
- Тесты:
  - `tests/test_consensus_rounds.py`
  - `tests/test_storage.py`
- Документация:
  - `docs/tasks/014-hashgraph-consensus-alignment.md`
  - `docs/architecture/architecture.md`
  - `docs/architecture/invariants.md`
  - `docs/architecture/review.md`
  - `docs/devplan/devplan.md`

## Acceptance Criteria
- [x] Появился `fame_needs_coin`.
- [x] Он persist-ится в SQLite и проходит через runtime.
- [x] Для unresolved history с двумя vote rounds выставляется `True`.
- [x] Для unresolved history только с initial vote round выставляется `False`.

## Verification
- [x] `python -m py_compile mdrj/consensus.py mdrj/models.py mdrj/storage.py mdrj/node.py tests/test_consensus_rounds.py tests/test_storage.py`
- [x] Добавлены unit/storage smoke tests на `fame_needs_coin`.
- [ ] Прогнать полноценный `pytest`, когда окружение будет содержать `pytest`.

## Rollback / Safety
Rollback возможен удалением `fame_needs_coin` без пересмотра уже введённых rounds, history и fame decision pipeline.

## Заметки
- Это ещё не coin round и не full Hedera voting.
- Но этот флаг даёт честную границу: обычный fame pipeline исчерпан, дальше нужен следующий protocol-step.
