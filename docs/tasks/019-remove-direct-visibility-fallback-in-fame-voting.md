# Task: Убрать Fallback На Прямую Видимость Из Fame Voting

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
После `018` fame pipeline уже хранит vote trace, но в поздних rounds ещё оставался упрощающий fallback: если witness не видел supermajority голосов предыдущего round, он возвращался к прямой видимости target witness. Это делало pipeline ближе к эвристике visibility, чем к настоящему round-by-round virtual voting.

## Цель
Сделать fame voting строже и ближе к hashgraph-подобной модели: поздние rounds должны использовать только видимые голоса предыдущего round, а не прямую видимость target witness как резервную эвристику.

## Scope
- Убрать fallback к `self._can_see(later_witness, target_witness)` для поздних rounds в fame pipeline.
- Ввести явное состояние `None` для нерешённого голоса witness в текущем round.
- Сохранять `vote_yes/vote_no` только по реально агрегированным голосам предыдущего round.
- Добавить тест на сценарий, где поздний round остаётся undecided именно из-за отсутствия достаточного числа видимых previous votes.

## Ограничения
- Не реализовывать full coin rounds или full Hedera `virtual voting`.
- Не менять membership snapshot semantics и quorum threshold.
- Не менять gossip transport, storage contracts событий и порядок `round_received -> consensus_ts -> event.id`.

## Текущее состояние
- Fame уже имеет explicit decision state и persisted vote trace.
- `round_received` уже умеет ждать более поздний round, если ранний fame round не дал quorum.
- Но поздний witness мог всё ещё “додумать” голос через прямую видимость, а не только через previous-round votes.

## Предлагаемое изменение
- Для round `r+1` initial vote остаётся based on direct visibility target witness.
- Для rounds `r+2` и позже голос witness вычисляется только по видимым голосам witnesses предыдущего round.
- Если supermajority `yes/no` по предыдущему round не видна, голос witness становится `None`, а не эвристическим `True/False`.

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
- [x] В rounds позже `r+1` fame voting больше не использует direct visibility fallback.
- [x] Нерешённый голос witness может быть `None`.
- [x] Vote trace `yes/no` считает только реально агрегированные голоса предыдущего round.
- [x] Есть тест на поздний round без quorum previous votes, где fame остаётся undecided без artificial yes/no.

## Verification
- [x] `python -m py_compile mdrj/consensus.py tests/test_consensus_rounds.py`
- [x] Добавлен unit-сценарий без quorum previous votes.
- [ ] Прогнать полноценный `pytest`, когда окружение будет содержать `pytest`.

## Rollback / Safety
Rollback возможен возвратом direct visibility fallback, не затрагивая membership snapshot, rounds, persisted vote trace и storage schema.

## Заметки
- Это всё ещё preparatory virtual voting, а не full Hedera parity.
- Следующий шаг: строить полный round-by-round voting/decision pipeline уже поверх tri-state голосов без visibility fallback.
