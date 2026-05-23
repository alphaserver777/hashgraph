# Task: Ввести Famous Witness Voting И Явное Решение Fame

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
После `014`, `015` и `016` проект уже имеет rounds, witnesses, preparatory famous witnesses, membership snapshot и новый deterministic order. Но fame всё ещё определяется эвристически по видимости в более поздних rounds. До hashgraph-подобного consensus всё ещё не хватает явного voting-layer: witness должен получать fame-решение не просто по visibility, а по цепочке vote/decide на последующих rounds.

## Цель
Перейти от preparatory famous witness heuristics к explicit fame decision pipeline, который станет непосредственной базой для `virtual voting`.

## Scope
- Ввести явные vote/decision states для witness fame.
- Определить по каким последующим rounds вычисляется голос `yes/no`.
- Ввести persisted признаки:
  - fame decided
  - fame value
  - round decided
- Убрать fallback-эвристику там, где fame уже начала решаться через voting pipeline.

## Ограничения
- Не делать weighted voting и stake-based модель.
- Не менять membership snapshot semantics.
- Не переписывать gossip transport.
- Не выдавать результат за полный Hedera parity без integration verification.

## Текущее состояние
- `round`, `round_received`, `is_witness`, `is_famous_witness` уже есть.
- Fame уже многораундовая, но ещё не имеет undecided/decided states.
- `round_received` пока может fallback-иться к ordinary witnesses.

## Предлагаемое изменение
- Построить explicit fame voting pipeline поверх witnesses более поздних rounds.
- Witness round `r` должен получать голос от witnesses следующих rounds на основе visibility.
- Когда достигается threshold и fame становится решённой, это состояние должно persist-иться и использоваться downstream без эвристического fallback.

## Затронутые области
- Код:
  - `mdrj/consensus.py`
  - `mdrj/models.py`
  - `mdrj/storage.py`
  - `mdrj/node.py`
- Тесты:
  - `tests/test_consensus_rounds.py`
  - новые integration-like сценарии voting/decision
- Документация:
  - `docs/tasks/014-hashgraph-consensus-alignment.md`
  - `docs/architecture/architecture.md`
  - `docs/architecture/review.md`
  - `docs/devplan/devplan.md`

## Acceptance Criteria
- [x] Fame имеет явное decided/undecided состояние.
- [x] Famous witness определяется через voting-like pipeline, а не только через visibility-эвристику.
- [x] Добавлены тесты на undecided -> decided переход.
- [x] `round_received` больше не fallback-ится к обычным witnesses в rounds, где fame уже начала решаться.
- [x] Событие может получить `round_received` на более позднем round, если более ранний round уже частично решался по fame, но ещё не дал quorum famous witnesses.
- [x] Документация явно отделяет этот шаг от полного `virtual voting`.

## Verification
- [x] `python -m py_compile mdrj/consensus.py mdrj/models.py mdrj/storage.py mdrj/node.py tests/test_consensus_rounds.py`
- [x] unit/integration-like сценарии voting pipeline добавлены в `tests/test_consensus_rounds.py`
- [x] проверка docs на согласованность
- [ ] Прогнать полноценный `pytest`, когда окружение будет содержать `pytest`.

## Rollback / Safety
Rollback возможен возвратом к multi-round preparatory fame logic без удаления membership snapshot и round pipeline.

## Заметки
- После этой задачи можно будет отдельно брать `virtual voting` как следующий узкий protocol-step, а не смешивать его с fame heuristics.
- Следующий follow-up на persisted vote provenance вынесен в `docs/tasks/018-fame-vote-trace-and-provenance.md`.
