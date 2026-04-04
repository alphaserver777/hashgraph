# MDRJ-DAG

Prototype implementation of the "минимально-достаточный распределённый журнал" (MDRJ) with a DAG-based event log, leaderless gossip, and deterministic event ordering. The goal is to replicate security events across heterogeneous nodes with prioritised delivery for critical incidents.

## Architecture Overview
- **DAG event log**: nodes try to attach each new event to up to two parents (latest local event, one recent remote event, then anchors as fallback), preserving causal context via vector clocks and parent edges.
- **Prioritised replication**: class `A` events always gossip; in the current implementation class `B` is also force-relayed, while class `C` flows on demand to keep the DAG closed.
- **Leaderless gossip**: fixed-interval epidemic exchange, fan-out `f`, deduplication, adaptive batches constrained by memory/bandwidth quotas.
- **Deterministic ordering heuristic**: each envelope accumulates hop timestamps; the current prototype derives `consensus_ts` from Lamport-style counters plus a deterministic source bias, raising it to the maximum observed hop timestamp when needed.
- **Local durability**: SQLite stores events, edges, envelopes, and peer health. No PoW, no fees, no external dependencies.
- **Runtime metrics**: availability estimate `A_est`, empirical gossip latency `T_gossip`, reconstruction factor `K_r`, memory/network pressure (`C_mem`, `C_net`).

## Project Layout
```
mdrj/
  api.py          # aiohttp HTTP API
  cli.py          # Typer CLI (`mdrj ...`)
  config.py       # YAML config loader
  consensus.py    # deterministic ordering heuristic + total order
  gossip.py       # epidemic fan-out loop
  metrics.py      # runtime metrics observer
  models.py       # dataclasses for Event / Envelope / NodeProfile
  node.py         # node lifecycle + state machine
  prioritization.py
  storage.py      # SQLite persistence
  utils.py        # helpers (hashing, median, etc.)
  vectorclock.py  # Lamport & vector clock utilities
configs/
  node.example.yaml
scripts/
  demo_start_cluster.sh
  demo_partition.sh
  demo_reconcile.sh
tests/
  ...
```

## Документация Проекта
Единственная рабочая точка правды по документации находится в [`docs/`](/home/admsys/hashgraph/docs):
- [`docs/WORKFLOW.md`](/home/admsys/hashgraph/docs/WORKFLOW.md) задаёт обязательный порядок работы.
- [`docs/constitution.md`](/home/admsys/hashgraph/docs/constitution.md) фиксирует инженерные правила проекта.
- [`docs/architecture/`](/home/admsys/hashgraph/docs/architecture) содержит текущее состояние системы, инварианты и обзор рисков.
- [`docs/devplan/devplan.md`](/home/admsys/hashgraph/docs/devplan/devplan.md) содержит среднесрочный план развития.
- [`docs/ops/DEPLOYMENT.md`](/home/admsys/hashgraph/docs/ops/DEPLOYMENT.md) фиксирует контур запуска и ограничения развёртывания.
- [`docs/ops/`](/home/admsys/hashgraph/docs/ops) содержит эксплуатационные и security-заметки.
- [`docs/review/review-log.md`](/home/admsys/hashgraph/docs/review/review-log.md) ведёт журнал важных проектных изменений.
- [`docs/templates/`](/home/admsys/hashgraph/docs/templates) хранит шаблоны для ADR и вспомогательных документов.
- [`docs/tasks/`](/home/admsys/hashgraph/docs/tasks) содержит task specs и правила ведения задач.
- [`docs/event-classification.md`](/home/admsys/hashgraph/docs/event-classification.md) является точкой правды для классификации известных типов событий.

Каталог [`.skaro/`](/home/admsys/hashgraph/.skaro) сохранён только как исторический след предыдущего этапа документирования. Использовать его как основной источник текущих правил и решений больше не нужно.

## Quick Start
1. **Install dependencies** (Python 3.11):
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e .
   ```
2. **Launch a node**:
   ```bash
   python -m mdrj.cli node --config configs/node.example.yaml
   ```
3. **Emit an event** (from another shell):
   ```bash
   python -m mdrj.cli emit --config configs/node.example.yaml --cls A --payload payload.json
   ```
4. **Inspect status/metrics**:
   ```bash
   python -m mdrj.cli status --config configs/node.example.yaml
   python -m mdrj.cli metrics --config configs/node.example.yaml
   python -m mdrj.cli metrics-watch --config configs/node.example.yaml --interval 1.0
   ```
   При обращении к удалённому узлу укажите `--api host:port`, например `python -m mdrj.cli metrics --config ... --api node1:9001`.
5. **Визуализация DAG**: откройте `http://127.0.0.1:9001/viz` и наблюдайте рост hashgraph в реальном времени. Цвет показывает класс события, ребро — ссылку ребёнка на родителя, номер `#` — позицию в итоговом порядке. Вверху страницы есть панель имитации (вирус, вход администратора, MAC-spoofing, порт-скан, heartbeat) — кнопки создают тестовые события прямо в браузере.

## Docker кластер

Собрать образ и запустить трёхузловой кластер можно через Docker Compose:

```bash
docker compose up --build -d node1 node2 node3
# После старта доступны HTTP порты 9101/9102/9103 на localhost, данные узлов лежат в томах node*-data (каталог /data внутри контейнера)
# Живой граф доступен в браузере: http://localhost:9101/viz (node2 → 9102/viz, node3 → 9103/viz)
```

Проверить состояние узлов:

```bash
docker compose ps
docker compose logs node1
docker compose exec node1 curl -s http://localhost:9001/status | jq
```

Выполнить сценарий «baseline» (создание событий и получение метрик) можно командой:

```bash
docker compose --profile demo-baseline up demo-baseline
```

Скрипт `docker/scripts/demo_baseline.sh` подождёт, пока все сервисы будут здоровы, сгенерирует события классов `A` и `B`, затем выведет актуальные метрики всех узлов. Кластеры можно гасить командой `docker compose down` (добавьте `-v`, если необходимо очистить тома данных).

### Linux bootstrap-узел

Для первого вертикального среза реального Linux ingestion в `docker-compose.yaml` есть отдельный профиль `linux-node`:

```bash
NODE_ID=linux-node-1 \
HOST_ID=linux-host-1 \
LISTEN=0.0.0.0:9011 \
LINUX_CONTAINER_PORT=9011 \
LINUX_PORT_BIND=9111 \
PEERS= \
docker compose --profile linux-node up --build -d linux-node
```

Этот режим не заменяет demo-кластер. Он поднимает отдельный self-contained узел, читает примонтированный `auth.log` и публикует минимальный production-oriented сигнал `admin_ssh_login_success` во внутренний DAG. Используется один универсальный конфиг `docker/configs/linux-node.yaml`; различия между серверами задаются env-переменными.
Локальная SQLite-база при этом живёт в volume `linux-node-data` на конкретном хосте.

## Running a Local Cluster
Use the helper script to spawn N nodes on one machine (default N=3, ports 9001+):
```bash
./scripts/demo_start_cluster.sh 3
```
Configuration files are generated under `configs/demo/`, logs under `logs/`. Manage processes via `ps`, `kill`, or by terminating the terminal session.

### Simulating Partitions & Healing
1. **Partition**: print suggested firewall rules for groups (e.g., split {1,2} from {3}):
   ```bash
   ./scripts/demo_partition.sh 1,2/3
   ```
   Apply the suggested `iptables` rules (requires root) to drop cross-group traffic.
2. **Emit events while isolated**: use `mdrj emit` against nodes in each partition.
3. **Heal**: remove the firewall rules (example command printed by `./scripts/demo_reconcile.sh`). Gossip queues re-announce stored events so the DAGs merge and `K_r` approaches 1.0.

## Acceptance Scenarios
1. **Baseline replication (3 nodes)**
   - Start cluster with `demo_start_cluster.sh 3`.
   - Emit mixed events on any node.
   - Observe all nodes converging (`mdrj dag --config ...`) and metrics reporting `A_est` ≈ 1.
2. **Partition and merge**
   - Split groups using firewall suggestions.
   - Emit events separately, then heal.
   - Watch `metrics` for `K_r ≥ 0.95`; the total order remains deterministic (`/dag`).
3. **Quota enforcement**
   - Configure a node with `profile.role=node`, low `bw_kbps`.
   - Flood with `mdrj emit` events (`--cls C`); `metrics` show `C_net ≤ 1` while `A` events always deliver.
4. **Node failures**
   - Start ≥5 nodes, stop one process.
   - Remaining nodes continue gossiping; `A_est` stays above quorum ratio.
5. **Idempotent delivery**
   - Re-submit past envelopes via `/event/batch`; DAG remains unchanged and consensus order identical (tests cover this determinism).

## HTTP API (JSON)
- `POST /event/emit` — Local emission (`{"cls": "A", "payload": {...}}`).
- `POST /event/batch` — Receive gossip envelopes; returns `{ "new": [ids] }`.
- `GET /dag/frontier` — Current frontier ids + vector clocks.
- `GET /dag` — Topological order of known events.
- `GET /peers` / `POST /peers/register` — Peer management.
- `GET /status` — FSM state, peers, profile.
- `GET /metrics` — Runtime metrics (`A_est`, `T_gossip`, `K_r`, `C_mem`, `C_net`).

All payloads are canonical JSON; signatures (HMAC-SHA256) are optional and configured per-node.

## Event Classes
The source-of-truth classification policy for known event kinds lives in [`docs/event-classification.md`](/home/admsys/hashgraph/docs/event-classification.md). The runtime mirror used by the application lives in [`mdrj/event_catalog.py`](/home/admsys/hashgraph/mdrj/event_catalog.py) and should be kept synchronized with that document.

## Testing
Run the unit and integration suite:
```bash
pytest
```
Key coverage:
- Vector/ Lamport clocks, DAG storage invariants.
- Prioritisation rules and batch planning.
- Deterministic ordering and partition/heal convergence scenarios.
- Multi-node gossip replication and partition/heal merge (`tests/test_gossip_integration.py`, `tests/test_merge_partition.py`).

## Extensibility & Limitations
- **Security**: swap HMAC for Ed25519 (`cryptography`) via pluggable signature module.
- **Transport**: MessagePack or QUIC transports can replace JSON/aiohttp.
- **Persistence**: SQLite can be swapped for Postgres or LMDB; current GC is coarse and may remove parent links needed for long-lived DAG reconstruction.
- **Policy**: integrate richer threat models or reputation scores for peer selection.
- **Monitoring**: expose Prometheus metrics; current CLI watcher handles basic observation.

This prototype focuses on clarity and testability; production deployments should harden security (TLS, mutual auth), add peer discovery, and implement automated partition controllers.
