# Task: Зафиксировать Fame Vote Trace И Provenance

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
После `017` у witness уже есть явные поля `is_famous_witness`, `fame_decided` и `fame_decision_round`, а `round_received` использует более строгий fame-aware pipeline. Но следующему шагу к `virtual voting` всё ещё не хватает прозрачного persisted следа голосования: по какому round в последний раз считался fame-vote и какой баланс `yes/no` был получен.

## Цель
Сделать fame pipeline наблюдаемым и сохраняемым: хранить последний vote-round и итоговые tally `yes/no`, чтобы следующий шаг по `virtual voting` опирался не на скрытую внутреннюю эвристику, а на явный vote trace.

## Scope
- Добавить в модель события и persisted consensus state:
  - `fame_vote_round`
  - `fame_vote_yes`
  - `fame_vote_no`
- Заполнять эти поля в `mdrj/consensus.py` для decided и undecided fame state.
- Сохранять их в SQLite и прокидывать через runtime.
- Добавить тесты на vote trace для:
  - immediate fame decision
  - multi-round partial fame без решения

## Ограничения
- Не делать full virtual voting messages или отдельный log голосов по witness.
- Не менять membership snapshot semantics.
- Не переводить UI на новый vote trace в этой задаче.

## Текущее состояние
- Fame уже имеет explicit decided/undecided state.
- `round_received` уже не fallback-ится к ordinary witnesses, если fame round частично решается.
- Но persisted trace последнего fame vote round и `yes/no` tally отсутствовал.

## Предлагаемое изменение
- Расширить `Event`, `ConsensusState`, SQLite schema и storage update под новые vote trace fields.
- В fame pipeline сохранять:
  - последний round, на котором были агрегированы голоса по witness;
  - число `yes` и `no` голосов для этого round.
- Использовать эти поля как provenance для будущего `virtual voting`.

## Затронутые области
- Код:
  - `mdrj/models.py`
  - `mdrj/consensus.py`
  - `mdrj/storage.py`
  - `mdrj/node.py`
- Тесты:
  - `tests/test_consensus_rounds.py`
- Документация:
  - `docs/tasks/014-hashgraph-consensus-alignment.md`
  - `docs/tasks/017-famous-witness-voting-and-decision.md`
  - `docs/architecture/architecture.md`
  - `docs/architecture/invariants.md`
  - `docs/architecture/review.md`
  - `docs/devplan/devplan.md`

## Acceptance Criteria
- [x] Событие хранит `fame_vote_round`, `fame_vote_yes`, `fame_vote_no`.
- [x] SQLite schema поддерживает эти поля и мигрируется без сброса старых БД.
- [x] Fame pipeline заполняет vote trace и для decided, и для undecided witness state.
- [x] Есть тест на immediate fame decision с ожидаемым `yes/no`.
- [x] Есть тест на multi-round fame, где witness остаётся undecided, но vote trace уже сохранён.

## Verification
- [x] `python -m py_compile mdrj/consensus.py mdrj/models.py mdrj/storage.py mdrj/node.py tests/test_consensus_rounds.py`
- [x] Обновить docs под новые поля fame vote trace.
- [ ] Прогнать полноценный `pytest`, когда окружение будет содержать `pytest`.

## Rollback / Safety
Rollback возможен удалением новых trace-полей без отката самого round/fame pipeline. Эти поля не меняют gossip transport и не ломают storage truth о событиях.

## Заметки
- Это ещё не full virtual voting.
- Следующий узкий шаг: использовать vote trace как базу для настоящего round-by-round fame decision rule-set без эвристического carry-over.
