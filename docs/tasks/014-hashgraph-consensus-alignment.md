# Task: Сблизить MDRJ-DAG С Hashgraph-Подобным Consensus Ordering

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
`in-progress`

## Контекст
Текущий репозиторий уже реализует DAG, gossip-распространение, локальное SQLite-хранение и детерминированное вычисление порядка событий. Но этот порядок пока не является полноценным hashgraph-consensus в смысле Hedera/Swirlds: проект не использует формализованные `rounds`, не выполняет `virtual voting` и не назначает `consensus timestamp` как результат сетевого наблюдения большинством узлов.

Сейчас NTP и единая временная зона помогают читать логи и сопоставлять события, но не могут быть источником истины для итогового порядка в распределённом реестре. Если два события создаются почти одновременно на разных узлах, проект должен упорядочивать их не только по локальным часам, а по воспроизводимому сетевому алгоритму.

## Цель
Определить пошаговый путь, который приблизит MDRJ-DAG к hashgraph-подобной модели консенсусного упорядочивания:
- `gossip about gossip`
- формальные `rounds`
- `virtual voting`
- `round received`
- `consensus timestamp`
- финальный детерминированный `tie-break`

## Scope
- Зафиксировать архитектурный разрыв между текущим порядком и hashgraph-подобным consensus.
- Определить минимальный набор данных, который должен сохраняться в событии и envelope для восстановления сетевого наблюдения.
- Описать целевую модель `rounds`, `virtual voting`, `round received` и `consensus timestamp`.
- Определить этапы миграции от текущего упрощённого порядка к новой модели.
- Определить критерии проверки и сценарии, которые покажут, что порядок больше не зависит только от локальных часов.

## Ограничения
- Эта задача не должна притворяться, что полноценный hashgraph-consensus уже реализован.
- В рамках этой задачи не нужно делать big bang refactor runtime, storage и API одновременно.
- NTP и `Europe/Moscow` остаются операционным требованием, но не должны использоваться как единственный источник порядка.
- Нужно сохранять совместимость с уже существующим DAG/gossip/storage контуром настолько, насколько это возможно.
- Любое изменение алгоритма порядка позже должно идти отдельными задачами и с явной verification.

## Текущее состояние
- У проекта есть локальный DAG, gossip и уже внедрён первый кодовый этап нового consensus pipeline.
- В runtime и SQLite теперь существуют явные поля:
  - `creator`
  - `self_parent_id`
  - `other_parent_id`
  - `round`
  - `round_received`
  - `is_witness`
- `consensus_ts` больше не считается по старой формуле `lamport + source bias + max(path_meta)` как источнику истины.
- Появился persisted `consensus membership snapshot` с epoch, который хранится отдельно от live peer-registry.
- Итоговый порядок уже перестроен на:
  1. `round_received`
  2. `consensus_ts`
  3. `event.id`
- Full `virtual voting` и полная fairness-модель Hedera всё ещё не реализованы, но fame-layer уже имеет explicit decision state и persisted vote trace (`fame_vote_round`, `fame_vote_yes`, `fame_vote_no`).

## Предлагаемое изменение
Разделить дальнейшее развитие consensus ordering на этапы. Первый этап уже реализован частично в коде и теперь должен быть зафиксирован в документации как новая база для следующих шагов.

### Этап 1. Явно зафиксировать текущий разрыв
- Документировать, что текущий `consensus_ts` является упрощённым приближением.
- Явно указать, что проект ещё не реализует hashgraph fairness/ordering в полном смысле.
- Запретить трактовать NTP как источник консенсуса.

### Этап 2. Усилить данные для `gossip about gossip`
- События и envelope уже расширены и несут:
  - `creator`
  - `self_parent_id`
  - `other_parent_id`
  - локальное время создания
  - `path_meta`
- Следующий шаг здесь не в добавлении новых полей любой ценой, а в проверке достаточности уже введённого контракта для будущего `virtual voting`.

### Этап 3. Ввести формальные `rounds`
- В коде уже введён первый deterministic rule-set:
  - событие наследует базовый round от родителей;
  - если оно видит supermajority witness текущего round, round повышается;
  - первое событие creator в своём round маркируется как witness;
  - `round_received` назначается минимальным round, где target event виден supermajority witness membership snapshot.
- Это ещё не Hedera-famous-witness voting и не окончательная fairness-модель.

### Этап 4. Ввести `virtual voting`
- Узлы по-прежнему не должны обмениваться отдельными голосами.
- Следующий protocol-step должен заменить текущий preparatory deterministic rule-set на модель, ближе к `virtual voting`.
- Нужно отдельно зафиксировать:
  - какие witness становятся кандидатами для голосования;
  - как определяется majority и famous witness;
  - как это влияет на `round_received`.

### Этап 5. Перейти к `consensus timestamp` по сетевому наблюдению
- В первом этапе это уже частично сделано:
  - `consensus_ts` считается только после появления `round_received`;
  - источником служат наблюдения из `path_meta`;
  - используется медиана наблюдений участников активного membership snapshot;
  - при недостатке наблюдений `consensus_ts` остаётся `NULL`.
- Следующий шаг должен усилить эту модель после появления настоящего `virtual voting`.

### Этап 6. Формализовать линейный порядок
- Итоговый порядок задаётся как:
  1. `round received`
  2. `consensus timestamp`
  3. жёсткий детерминированный `tie-break`
- Этот порядок должен давать одинаковый результат на всех узлах при одинаковом DAG.

### Этап 7. Верифицировать плохие сценарии
- Два события одновременно на разных узлах.
- Разная задержка gossip.
- Partition / split-brain с последующим восстановлением.
- Узел с плохими часами.
- Узел, который пытается сместить время события.

## Затронутые области
- Код:
  - `mdrj/consensus.py`
  - `mdrj/node.py`
  - `mdrj/storage.py`
  - `mdrj/models.py`
  - `mdrj/api.py`
  - `mdrj/gossip.py`
- Тесты:
  - `tests/test_consensus_rounds.py`
  - интеграционные сценарии порядка
  - сценарии конкурирующих одновременных событий
  - сценарии partition/recovery
- Документация:
  - `docs/architecture/architecture.md`
  - `docs/architecture/review.md`
  - `docs/devplan/devplan.md`
- Deploy / Infra:
  - напрямую не входит, кроме сохранения требования NTP как операционного baseline

## Acceptance Criteria
- [x] В документации явно зафиксировано, что текущий `consensus_ts` ещё не равен полноценному hashgraph-consensus.
- [x] Зафиксирована целевая модель `rounds -> virtual voting -> round received -> consensus timestamp -> tie-break`.
- [x] Определён минимальный набор данных, который должен существовать в runtime для перехода к этой модели.
- [x] Определены этапы реализации без big bang refactor.
- [x] Добавлен первый кодовый этап: `rounds`, `round_received`, frozen membership snapshot и новый reference-порядок.
- [x] `/status` теперь показывает active consensus membership и явное состояние mismatch/pending по peer snapshots.
- [x] Зафиксировано, что NTP обязателен для операционной точности, но не является источником консенсусного порядка.
- [ ] Определён и подтверждён набор integration verification-сценариев для одновременных событий, сетевых задержек и partition/recovery.

## Verification
- [x] `python -m py_compile mdrj/api.py mdrj/node.py mdrj/storage.py mdrj/models.py mdrj/consensus.py tests/test_consensus_rounds.py tests/test_storage.py tests/test_peer_registry.py`
- [x] Проверить согласованность `docs/architecture/architecture.md`, `docs/architecture/invariants.md` и этой задачи.
- [x] Проверить, что документы не утверждают, будто full hashgraph-consensus уже реализован.
- [x] Проверить, что devplan отражает это как отдельное protocol-направление, а не как побочную UI или deploy-задачу.
- [x] Проверить, что follow-up по коду можно разбить на отдельные задачи без архитектурного расползания.
- [x] Добавить unit/integration-like сценарии в `tests/test_consensus_rounds.py` для:
  - одновременных корневых событий с последующей сходимостью порядка;
  - игнорирования наблюдений узлов вне active membership snapshot.
- [ ] Прогнать полноценный `pytest`, когда окружение будет содержать зависимость `pytest`.
- [ ] Добавить и прогнать integration-сценарии на одновременные события, плохие часы и partition/recovery.

## Rollback / Safety
Документационный rollback должен просто удалить или откатить этот protocol-план, не меняя текущий runtime. На этапе проектирования нельзя делать скрытые изменения, которые создадут ложное ощущение уже реализованного Hedera-подобного порядка.

## Заметки
- Hedera/Swirlds используется как референс по направлению развития, но текущий проект не должен притворяться их production-реализацией.
- Уже реализованный первый кодовый слой включает:
  - persisted `consensus membership snapshot`
  - explicit `reconfigure consensus membership`
  - поля `round`, `round_received`, `is_witness`
  - новый порядок `round_received -> consensus_ts -> event.id`
- Следующие практические задачи после этой должны быть узкими:
  - famous witnesses и `virtual voting`
  - stronger `round_received`
  - integration-тесты на сходимость порядка
  - диагностика mismatch active membership snapshots между узлами

Текущий follow-up вынесен в `docs/tasks/015-preparatory-famous-witnesses.md`.
Следующий follow-up после `015` вынесен в `docs/tasks/016-multi-round-famous-witness-resolution.md`.
Следующий active step после `016` оформлен в `docs/tasks/017-famous-witness-voting-and-decision.md`.
Следующий follow-up после `017` оформлен в `docs/tasks/018-fame-vote-trace-and-provenance.md`.
Следующий шаг по сближению с `virtual voting` оформлен в `docs/tasks/019-remove-direct-visibility-fallback-in-fame-voting.md`.
Следующий внутренний protocol-step с explicit round-by-round vote history оформлен в `docs/tasks/020-round-by-round-fame-vote-history.md`.
Следующий формальный decision-step поверх history оформлен в `docs/tasks/021-formal-fame-decision-from-vote-history.md`.
Следующий шаг на более строгий `round_received` оформлен в `docs/tasks/022-require-fully-decided-fame-rounds-for-round-received.md`.
Следующий preparatory step для перехода к coin/voting phase оформлен в `docs/tasks/023-mark-unresolved-fame-as-needing-coin-step.md`.
Следующий bridge-step с deterministic coin surrogate оформлен в `docs/tasks/024-deterministic-coin-surrogate-for-fame.md`.
Следующий шаг на явное разделение vote-решения и surrogate decision-kind оформлен в `docs/tasks/025-explicit-fame-decision-kind.md`.
