# Task: Выделить Формальный Fame Decision Layer Поверх Vote History

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
После `020` fame voting уже имеет explicit round-by-round history, но итоговое fame decision ещё вычислялось внутри того же helper, который строит эту историю. Для следующего шага к более строгому `virtual voting` нужен отдельный формальный слой принятия решения: история голосов должна строиться отдельно, а fame-result получаться отдельным resolver.

## Цель
Разделить два понятия:
- построение vote history по раундам;
- принятие fame decision по этой истории.

## Scope
- Вынести отдельный helper `resolve_fame_from_vote_history`.
- Принцип решения:
  - самый ранний round с supermajority `yes` или `no` фиксирует fame decision;
  - более поздние rounds уже не должны переопределять ранее принятое решение.
- Если решения нет, resolver возвращает последнее наблюдаемое tally без `decided=True`.

## Ограничения
- Не вводить coin rounds и не моделировать полный Hedera voting.
- Не менять storage schema и внешние runtime contracts.
- Не делать persistence полной history; этот шаг остаётся внутренним protocol-layer.

## Текущее состояние
- Fame уже имеет:
  - explicit decision state
  - vote trace
  - tri-state late-round votes
  - round-by-round internal vote history
- Но decision ещё не был выделен как отдельный формальный этап.

## Предлагаемое изменение
- Строить history в одном helper.
- Разрешать fame в отдельном helper по правилу earliest decisive round wins.
- Проверить тестами:
  - решение фиксируется на первом решающем round;
  - поздняя conflicting history не переопределяет решение;
  - при отсутствии решения наружу выходит последний observed tally.

## Затронутые области
- Код:
  - `mdrj/consensus.py`
- Тесты:
  - `tests/test_consensus_rounds.py`
- Документация:
  - `docs/tasks/014-hashgraph-consensus-alignment.md`
  - `docs/architecture/architecture.md`
  - `docs/architecture/review.md`
  - `docs/devplan/devplan.md`

## Acceptance Criteria
- [x] Fame decision вычисляется отдельным resolver поверх vote history.
- [x] Earliest decisive round wins.
- [x] Более поздние rounds не переопределяют уже принятое fame decision.
- [x] Есть тест на unresolved history и возврат последнего observed tally.

## Verification
- [x] `python -m py_compile mdrj/consensus.py tests/test_consensus_rounds.py`
- [x] Добавлены unit-тесты на formal fame decision resolver.
- [ ] Прогнать полноценный `pytest`, когда окружение будет содержать `pytest`.

## Rollback / Safety
Rollback возможен возвратом к inline fame-decision внутри history-builder без изменения storage и без потери уже введённых runtime-полей.

## Заметки
- Это всё ещё preparatory step перед более полным `virtual voting`.
- Следующий шаг: расширять ruleset decision rounds и переходить к более hashgraph-подобной схеме fame voting.
