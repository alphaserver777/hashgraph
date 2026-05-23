# 025. Явный `fame_decision_kind`

Статус: `completed`

## Контекст
После шага с deterministic coin surrogate persisted fame-state уже умеет закрывать зависшие witness cases. Но downstream пока видит это только через комбинацию флагов `fame_coin_used`, `fame_decided` и `fame_needs_coin`. Для следующего сближения с Hedera-подобным алгоритмом этого мало: нужно явное поле, которое различает качество и происхождение fame-решения.

## Решение
- Ввести persisted поле `fame_decision_kind`.
- Допустимые значения v1:
  - `pending`
  - `vote`
  - `coin_surrogate`
- `vote` означает, что fame решена обычным voting tally.
- `coin_surrogate` означает, что ordinary voting не дало решения и был применён текущий bridge-step surrogate coin.
- `pending` означает, что fame ещё не решена и coin-step ещё не применялся.

## Изменения
- Расширить runtime/datamodel:
  - `mdrj/models.py`
  - `mdrj/consensus.py`
- Расширить SQLite schema и миграцию:
  - `mdrj/storage.py`
- Прокинуть поле в persisted consensus-state:
  - `mdrj/node.py`
- Обновить unit/smoke tests:
  - `tests/test_consensus_rounds.py`
  - `tests/test_storage.py`

## Acceptance Criteria
- `vote`-решение fame сохраняется как `fame_decision_kind = "vote"`.
- surrogate coin-решение fame сохраняется как `fame_decision_kind = "coin_surrogate"`.
- unresolved fame остаётся с `fame_decision_kind = "pending"`.
- Новое поле переживает рестарт и читается из SQLite через `Event.from_record()`.
- Документация явно фиксирует, что `fame_decision_kind` отделяет нормальный voting path от временного surrogate path.

## Verification
- `python -m py_compile mdrj/consensus.py mdrj/models.py mdrj/storage.py mdrj/node.py tests/test_consensus_rounds.py tests/test_storage.py`
- Проверить, что `tests/test_consensus_rounds.py` покрывает:
  - обычное vote-решение
  - unresolved pending
  - surrogate coin-решение
- Проверить, что `tests/test_storage.py` сохраняет и читает `fame_decision_kind`.

## Ограничения
- Это не меняет саму fame semantics.
- Это только делает provenance решения явным и устойчивым для следующих protocol-этапов.
