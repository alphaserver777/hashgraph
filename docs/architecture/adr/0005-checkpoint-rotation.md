# ADR-0005: Checkpoint механизм для ротации распределённого реестра

## Статус
Принято (этап 3.a прототипа). Этот ADR описывает только **механизм** checkpoint (Merkle + 2/3 quorum signatures). Связанные с ним GC, retention policy, event_skeleton и cold archive описаны отдельно в ADR-0006 (этап 3.b).

## Контекст
Распределённый реестр на DAG растёт линейно с потоком событий ИБ. Простой rolling GC по возрасту (как существующий `gc_by_quota`) сносит старые события вместе с edges, что разрушает причинную цепь и убирает криптографическую проверяемость прошлого. Это **противоречит цели диссертации** — защите от УБИ.124. Атакующий, получивший доступ к узлу и зная политику ротации, мог бы дождаться удаления компрометирующих событий и заявить, что их «никогда не было».

Нужен механизм, который позволяет ограничивать размер горячего хранилища, **сохраняя криптографическую проверяемость уже произошедших событий**. Этот ADR описывает такой механизм.

## Решение
Введено понятие **checkpoint**: подписанный множеством узлов снэпшот состояния реестра до `round_received = N`. Это «якорь», под которым историю можно сжимать (этап 3.b), не теряя возможности доказать целостность.

### Структура checkpoint
В новой таблице `checkpoints` хранятся:
- `round_received` — целевая граница (PK).
- `merkle_root` — детерминированный SHA-256 от всех событий с `round_received ≤ N`. Каждый «лист» — это SHA-256 от canonical-JSON `{id, cls, creator, parents, consensus_ts, round_received, payload_hash}`. Листья сортируются по `(round_received, id)`. Корень — flat SHA-256 от конкатенации листьев (не классическое дерево; см. Ограничения).
- `members_snapshot_hash` — указатель на frozen membership snapshot, под которым checkpoint был произведён. Это нужно, чтобы при изменении membership старые checkpoint остались верифицируемыми.
- `signatures` (JSON) — map `node_id → hex HMAC-SHA256 над canonical body proposal`. HMAC-ключ берётся из общего `security.hmac_key` (см. Ограничения про Ed25519).
- `status` ∈ {`pending`, `confirmed`}. `confirmed` если подписей ≥⌈2N/3⌉ от размера membership.
- `confirmed_at` — timestamp перехода в confirmed.

### Lifecycle
1. **Proposal:** оператор или фоновая задача вызывает `Node.propose_local_checkpoint(target_round)`. Узел вычисляет merkle, подписывает proposal своим `hmac_key`, и записывает pending checkpoint с одной подписью (своей). Возвращает proposal-словарь.
2. **Broadcast** (вне этого ADR): proposal рассылается peer-ам через `POST /checkpoint/propose`.
3. **Ingestion:** peer-узел получает proposal, через `ingest_checkpoint_proposal()` проверяет HMAC, и:
   - Если merkle_root совпадает с локально вычисленным (или с существующим pending) → добавляет подпись proposer-а к set-у подписей.
   - Если merkle_root **отличается** → **proposal отвергается** и пишется warning. Это первая линия обнаружения tampering в реальном времени.
4. **Confirmation:** при достижении `is_quorum_reached` (≥⌈2N/3⌉ от members snapshot) checkpoint переводится в `confirmed`.
5. **Verification:** `Node.verify_checkpoint(round)` перерабатывает merkle из локальных событий и сравнивает с подтверждённым. Если расхождение **и checkpoint=confirmed** — флаг `has_tamper_evidence=True`.

### HTTP API
- `POST /checkpoint/propose` без body или с `{round_received}` → создаёт локальный proposal.
- `POST /checkpoint/propose` с full proposal body (от peer-а) → ingestion-путь.
- `GET /checkpoint/list?status=confirmed&limit=10` → список checkpoint'ов.
- `GET /checkpoint/verify?round_received=N` → отчёт верификации `{matches_merkle, local_merkle_root, confirmed_merkle_root, has_tamper_evidence, notes}`.

Все state-changing endpoints защищены HMAC middleware (ADR-0002).

### Quorum формула
`threshold = ⌈2N/3⌉` для membership size N. Реализована как `(2N + 2) // 3` в `is_quorum_reached`.

Примеры:
- N=3: threshold=2 → достаточно 2 подписей.
- N=4: threshold=3.
- N=5: threshold=4.
- N=7: threshold=5.

## Последствия

**Положительные:**
- **Защита от УБИ.124.** Подтверждённый checkpoint фиксирует состояние реестра подписями ≥2/3 узлов. Чтобы подделать историю до `round_received=N` без обнаружения, атакующий должен скомпрометировать ≥2/3 узлов одновременно — на порядок выше барьер, чем компрометация одного SIEM-сервера.
- **Tamper detection в реальном времени** через `/checkpoint/verify` — узел, у которого payload какого-то старого события был изменён, сразу даёт mismatch при первой же `verify` и явный `has_tamper_evidence: true` флаг.
- **Открыта дорога к GC.** Этап 3.b может безопасно удалять payloads событий с `round_received ≤ confirmed_checkpoint.round_received`, сохраняя только `event_skeleton`-ы (parent_ids + payload_hash). Causal chain остаётся проверяемой, payload — нет, но это компромисс хранения, не безопасности.

**Отрицательные / ограничения:**
- **Flat hash, не классический Merkle tree.** Текущий алгоритм даёт ту же tamper-evidence гарантию при фиксированном наборе событий, но **не поддерживает inclusion proofs** для отдельных событий. Если потребуется доказать «это конкретное событие было в реестре на момент checkpoint=N», без локальной копии реестра это невозможно. Production-итерация должна заменить на binary Merkle tree.
- **HMAC общим ключом.** Все узлы используют один и тот же `security.hmac_key`. Утечка на одном узле даёт атакующему возможность подделать подпись от лица любого узла. Это приемлемо для прототипа диссертационной защиты, **не приемлемо для production**. Открытый вопрос плана (Ed25519 per-node keypair) явно сюда.
- **Quorum считается от frozen membership snapshot.** Если membership меняется между proposal и confirmation, threshold может оказаться рассогласованным. Текущая реализация использует `active_consensus_membership()` на момент `_record_proposal_signature`, что снижает риск, но не устраняет полностью.
- **Proposal с разным merkle_root отвергается, а не «голосуется».** Если в network есть split-brain (две группы видят разный реестр), checkpoint не достигнет quorum, и оператор увидит `pending` с подписями только от одной стороны. Это **правильное** поведение — мы не хотим автоматически выбрать одну версию истории. Но это требует ручного вмешательства оператора в случае split-brain.
- **Broadcast не реализован.** В этом этапе propose/ingest endpoints есть, но автоматической рассылки proposal по peer-ам нет. Оператор должен дёргать `POST /checkpoint/propose` на каждом узле, или этап 3.b добавит фоновый proposal-loop.
- **Verify сообщает tamper только при mismatch у `confirmed` checkpoint.** Если checkpoint ещё `pending`, mismatch может быть результатом legitimate race condition (узел не догнал какие-то события).

## См. также
- [ADR-0002](0002-hmac-api-auth.md) — HMAC для transport, который checkpoint-API тоже использует.
- [ADR-0003](0003-collectors-package.md) — коллекторы добавляют события в реестр; checkpoint их «замыкает».
- [ADR-0006](0006-retention-and-archive.md) (будущий, этап 3.b) — что мы делаем со старыми событиями после checkpoint.
- [docs/devplan/devplan.md](../../devplan/devplan.md) этап 2.1 «Schema change и миграции» и этап 2.3 «Transport hardening».
- Открытый вопрос плана: HMAC vs Ed25519 для подписи checkpoints. См. [/home/admsys/.claude/plans/quirky-whistling-clover.md](../../../../../.claude/plans/quirky-whistling-clover.md).
