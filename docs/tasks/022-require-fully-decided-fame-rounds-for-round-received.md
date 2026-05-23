# Task: Требовать Полностью Решённый Fame Round Для `round_received`

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
После `021` fame voting уже имеет explicit history и formal decision resolver. Но `round_received` всё ещё мог использовать round, в котором fame была решена только частично: достаточно было наличия некоторого числа decided-famous witnesses. Для более строгой hashgraph-подобной модели это слишком рано.

## Цель
Сделать `round_received` строже: round может использоваться по famous witnesses только тогда, когда fame в этом round решена полностью для всех witnesses этого round.

## Scope
- Изменить `round_received`:
  - если fame round полностью решён, использовать только famous witnesses;
  - если fame round частично решён, пропускать round целиком;
  - если fame round ещё не начал решаться, можно использовать обычных witnesses.
- Добавить тест на частично решённый fame round.

## Ограничения
- Не менять quorum threshold.
- Не менять storage schema.
- Не менять deterministic total order `round_received -> consensus_ts -> event.id`.

## Текущее состояние
- Fame уже имеет explicit decision state.
- Но частично решённый fame round мог всё ещё слишком рано влиять на `round_received`.

## Предлагаемое изменение
- Partial fame resolution в round больше не должна быть достаточной.
- Пока round не закрыт по fame целиком, `round_received` обязан ждать либо:
  - полного решения fame этого round,
  - либо более позднего round, который даст quorum по своим witness/fame rules.

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
- [x] Частично решённый fame round больше не участвует в `round_received`.
- [x] Полностью решённый fame round по-прежнему участвует в `round_received` через famous witnesses.
- [x] Добавлен тест на partial fame round.

## Verification
- [x] `python -m py_compile mdrj/consensus.py tests/test_consensus_rounds.py`
- [x] Добавлен unit-сценарий на partial fame round.
- [ ] Прогнать полноценный `pytest`, когда окружение будет содержать `pytest`.

## Rollback / Safety
Rollback возможен возвратом к предыдущему правилу `any decided -> use famous subset`, не затрагивая history, vote trace и fame resolver.

## Заметки
- Это ещё не full Hedera parity.
- Но это делает `round_received` заметно строже и ближе к модели, где round нельзя использовать до завершения решения fame.
