# Task: Перевести Fame Resolution На Многораундовую Модель

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
`015` добавила fame-метку witness-событий по упрощённому next-round правилу. Это полезный preparatory шаг, но всё ещё слишком жёсткий: witness должен становиться famous не только если его уже видит supermajority следующего round, но и если эта supermajority сформировалась в более позднем round.

## Цель
Сделать fame resolution многораундовым, чтобы preparatory famous witness logic приблизилась к voting-like модели и перестала зависеть только от ближайшего следующего round.

## Scope
- Изменить fame resolution так, чтобы witness мог стать famous по supermajority наблюдений из любого более позднего round.
- Добавить тест на сценарий, где fame не определяется в `round + 1`, но определяется позже.
- Зафиксировать это как следующий preparatory шаг перед full `virtual voting`.

## Ограничения
- Не реализовывать full vote propagation и undecided/decided states Hedera.
- Не вводить отдельные сообщения голосования.
- Не менять `round_received` beyond использования обновлённого fame resolution.
- Не утверждать, что это уже production-famous-witness protocol.

## Текущее состояние
- `is_famous_witness` уже существует.
- Fame witness уже сохраняется в SQLite.
- `round_received` уже предпочитает famous witnesses, если их достаточно.
- Но fame определялась только по ближайшему следующему round.

## Предлагаемое изменение
- Famous witness определяется по самому раннему более позднему round, где supermajority witness видит candidate witness.
- Если `round + 1` ещё не даёт quorum, fame может быть определена на `round + 2` и дальше.
- Это приближает проект к voting-like semantics без полного внедрения `virtual voting`.

## Затронутые области
- Код:
  - `mdrj/consensus.py`
- Тесты:
  - `tests/test_consensus_rounds.py`
- Документация:
  - `docs/tasks/015-preparatory-famous-witnesses.md`
  - `docs/tasks/014-hashgraph-consensus-alignment.md`
  - `docs/architecture/architecture.md`
  - `docs/architecture/review.md`
  - `docs/devplan/devplan.md`
- Deploy / Infra:
  - не затрагивается

## Acceptance Criteria
- [x] Fame resolution больше не ограничена только `round + 1`.
- [x] Добавлен тест, где witness становится famous по более позднему round.
- [x] В документации явно указано, что это ещё не full `virtual voting`.

## Verification
- [x] `python -m py_compile mdrj/consensus.py tests/test_consensus_rounds.py`
- [x] Ручной smoke на synthetic DAG подтверждает fame по более позднему round.
- [ ] Прогнать полноценный `pytest`, когда окружение будет содержать `pytest`.

## Rollback / Safety
Rollback возможен возвратом к next-round fame rule. Это изменит только semantics fame resolution и не требует отката schema.

## Заметки
- Следующий настоящий шаг после этой задачи: full famous witness voting с явным undecided/decided pipeline, а затем `virtual voting`.
