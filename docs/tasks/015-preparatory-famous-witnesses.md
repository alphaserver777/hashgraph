# Task: Добавить Preparatory Famous Witnesses В Hashgraph-Подобный Consensus

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
В `014` уже внедрён первый кодовый этап hashgraph-подобного порядка: frozen membership snapshot, `round`, `round_received`, `is_witness` и новый reference-порядок. Следующий узкий шаг должен приблизить проект к Hedera без big bang: добавить preparatory famous witnesses как промежуточный слой перед full `virtual voting`.

## Цель
Добавить в runtime и storage явную fame-метку witness-событий и начать использовать её при определении `round_received`, сохранив deterministic behavior и не вводя ещё полный алгоритм famous witness voting.

## Scope
- Ввести `is_famous_witness` в runtime model и SQLite.
- Определять famous witness по упрощённому next-round правилу.
- Использовать famous witnesses при определении `round_received`, когда fame уже известна для соответствующего round.
- Добавить тесты на fame для witness-событий и на сходимость порядка.
- Зафиксировать это в архитектурных документах как preparatory шаг, а не как full Hedera voting.

## Ограничения
- Не реализовывать full `virtual voting`.
- Не вводить weighted membership, роли или trust-модель в consensus.
- Не менять gossip/API/storage больше, чем нужно для fame-метки и её persistence.
- Не утверждать в docs, что famous witness selection уже соответствует Hedera production semantics.

## Текущее состояние
- Witness-события уже вычисляются.
- `round_received` пока считается по witness-множеству round с fallback на deterministic majority rule.
- `consensus_ts` уже зависит от `round_received` и `path_meta`.
- В хранилище ещё нет отдельного persisted признака fame witness.

## Предлагаемое изменение
- Witness данного round считается famous, если его видит supermajority witness следующего round.
- `round_received` должен предпочитать famous witnesses соответствующего round, если их достаточно для supermajority; иначе допускается fallback к обычным witnesses.
- Fame-метка должна сохраняться в `events` и передаваться через model/API/UI payload так же, как `is_witness`.
- Этот шаг считается preparatory voting-layer, а не завершённым famous witness protocol.

## Затронутые области
- Код:
  - `mdrj/consensus.py`
  - `mdrj/models.py`
  - `mdrj/storage.py`
  - `mdrj/node.py`
- Тесты:
  - `tests/test_consensus_rounds.py`
  - `tests/test_storage.py`
- Документация:
  - `docs/tasks/014-hashgraph-consensus-alignment.md`
  - `docs/architecture/architecture.md`
  - `docs/architecture/review.md`
  - `docs/devplan/devplan.md`
- Deploy / Infra:
  - не затрагивается

## Acceptance Criteria
- [x] В runtime model есть `is_famous_witness`.
- [x] SQLite хранит fame-метку witness-событий.
- [x] `round_received` учитывает famous witnesses там, где fame уже определена.
- [x] Добавлены тесты, подтверждающие, что root witnesses могут стать famous после появления следующего round.
- [x] В документации явно указано, что это ещё не full `virtual voting`.

## Verification
- [x] `python -m py_compile mdrj/consensus.py mdrj/models.py mdrj/storage.py mdrj/node.py tests/test_consensus_rounds.py tests/test_storage.py`
- [x] Ручной smoke `ConsensusEngine.recompute(...)` на multi-round сценарии подтверждает `is_famous_witness=True` для round-0 witnesses.
- [ ] Прогнать полноценный `pytest`, когда окружение будет содержать `pytest`.

## Rollback / Safety
Rollback возможен откатом fame-поля и возвратом `round_received` к witness-only правилу. Это не требует отката schema beyond removing/ignoring `is_famous_witness`, но при rollback нужно сохранить читаемость существующих SQLite-данных.

## Заметки
- Следующим шагом после этой задачи должен быть уже настоящий famous witness / `virtual voting` protocol-step без fallback на ordinary witnesses.
- Fallback к обычным witnesses оставлен намеренно, чтобы не обрушить determinism на неполных DAG в переходной версии.
