# Task: Ввести Round-By-Round Историю Голосов Для Fame

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
После `019` fame voting больше не fallback-ится к прямой видимости в поздних rounds, но internal pipeline всё ещё сводился к одному циклу с `previous_votes/current_votes`. Для следующего шага к настоящему `virtual voting` нужно явное round-by-round представление голосов: по каждому target witness должно быть видно, какие именно голоса существовали в каждом vote round.

## Цель
Сделать fame voting структурно прозрачным: строить explicit vote history по раундам и вычислять fame decision уже поверх этой истории.

## Scope
- Вынести internal helper, который строит:
  - `vote_history[target_round][target_witness][vote_round][voter_creator] = vote`
- Использовать эту историю для итогового fame decision state.
- Добавить тесты на round-by-round vote history.

## Ограничения
- Не делать persistent storage всей истории голосов по witness.
- Не реализовывать coin rounds, randomization и full Hedera parity.
- Не менять external API и storage schema событий.

## Текущее состояние
- Fame уже имеет decision state, vote trace и tri-state поздних голосов.
- Но round-by-round history существовала только неявно внутри одного цикла.

## Предлагаемое изменение
- Ввести явную internal историю голосов по раундам.
- Initial votes `r+1` остаются direct-visibility based.
- Поздние rounds формируются только из видимых votes предыдущего round.
- Fame decision по witness вычисляется из этой истории, а не из неявного carry-over.

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
- [x] Есть explicit internal helper для round-by-round vote history.
- [x] Fame decision вычисляется поверх этой истории.
- [x] Добавлен unit-test, который проверяет history по round для target witness.
- [x] Документация фиксирует, что это ещё preparatory step, а не full `virtual voting`.

## Verification
- [x] `python -m py_compile mdrj/consensus.py tests/test_consensus_rounds.py`
- [x] Добавлены unit-сценарии на vote history.
- [ ] Прогнать полноценный `pytest`, когда окружение будет содержать `pytest`.

## Rollback / Safety
Rollback возможен возвратом к прежнему `previous_votes/current_votes` циклу без изменения storage и runtime contracts.

## Заметки
- Этот шаг сознательно внутренний: history не persist-ится как отдельный storage contract.
- Следующий шаг: уже поверх этой структуры делать более полный famous witness voting / `virtual voting` decision rule-set.
