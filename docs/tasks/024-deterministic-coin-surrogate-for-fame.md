# Task: Ввести Deterministic Coin Surrogate Для Нерешённого Fame

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
После `023` fame pipeline уже умел явно отличать unresolved cases, дошедшие до стадии `needs_coin`. Но сами такие случаи ещё не закрывались: система только сигнализировала, что следующий этап должен использовать coin-step. Для продолжения protocol-track нужен bridge-механизм, который позволит завершать такие fame cases без притворства, что full Hedera coin rounds уже реализованы.

## Цель
Ввести deterministic coin surrogate для unresolved fame cases после нескольких vote rounds.

## Scope
- Добавить:
  - `fame_coin_used`
  - `fame_coin_round`
- Если fame не решена и ordinary vote pipeline исчерпан:
  - использовать deterministic coin surrogate на основе `witness_id + vote_round`
  - закрывать fame decision этим значением
- Не использовать surrogate, если есть только initial vote round.

## Ограничения
- Это не настоящий Hedera coin round.
- Не вводить случайность, внешние entropy-source или distributed coin protocol.
- Не менять deterministic total order и membership snapshot semantics.

## Текущее состояние
- Fame уже имеет:
  - explicit decision state
  - vote trace
  - round-by-round history
  - strict `round_received`
  - `fame_needs_coin`
- Но unresolved fame после нескольких vote rounds ещё не получала итогового решения.

## Предлагаемое изменение
- Ввести helper deterministic coin surrogate.
- После исчерпания ordinary voting:
  - `fame_decided=True`
  - `fame_coin_used=True`
  - `fame_coin_round = last_vote_round`
  - `fame_needs_coin=False`
- Хранить это в SQLite и runtime.

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
- [x] Появились `fame_coin_used` и `fame_coin_round`.
- [x] Unresolved fame после нескольких vote rounds закрывается deterministic coin surrogate.
- [x] Initial unresolved vote round не использует coin surrogate преждевременно.
- [x] Добавлены тесты на coin surrogate и storage persistence.
- [x] Документация явно утверждает, что это surrogate, а не full Hedera coin round.

## Verification
- [x] `python -m py_compile mdrj/consensus.py mdrj/models.py mdrj/storage.py mdrj/node.py tests/test_consensus_rounds.py tests/test_storage.py`
- [x] Synthetic smoke на deterministic coin surrogate.
- [ ] Прогнать полноценный `pytest`, когда окружение будет содержать `pytest`.

## Rollback / Safety
Rollback возможен возвратом к `fame_needs_coin` без автоматического surrogate-decision. Это не требует отката rounds, history, vote trace или membership snapshot.

## Заметки
- Это preparatory bridge-step.
- Следующий честный шаг: заменить surrogate на более hashgraph-подобный fame decision rule-set / настоящий следующий virtual-voting этап.
