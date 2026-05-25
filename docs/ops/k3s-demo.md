# Запуск демо-стенда MDRJ-DAG в k3s/k3d (Zomro VPS)

Цель документа — пошагово развернуть 5-узловой тестовый стенд MDRJ-DAG на чистом Linux-сервере (Zomro VPS), нагрузить его и продемонстрировать ключевые свойства для дисс-защиты:
1. Линейная масштабируемость и устойчивость к падению узлов.
2. Real-time tamper detection через checkpoint verify.
3. Эмпирические метрики (`bytes_per_event`, `db_size`, latency) для калибровки A4 в `diser_models/simulation.html`.

## Минимальные требования к серверу

| Параметр | Значение |
|---|---|
| CPU | 2 vCPU |
| RAM | 4 GB (для 5 узлов с запасом) |
| Disk | 10 GB |
| OS | Ubuntu 22.04 / Debian 12 |
| Сеть | публичный IP, открыт порт 30901/tcp |

## 1. Подготовка хоста

```bash
# Подключение
ssh root@<zomro-ip>

# Базовые пакеты
apt update && apt install -y curl ca-certificates git openssl jq python3 python3-pip

# Docker (официальный installer)
curl -fsSL https://get.docker.com | sh

# k3d (k3s в Docker)
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash

# kubectl (k3d-bundled)
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
install -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl

# Проверка
docker --version
k3d --version
kubectl version --client
```

## 2. Клонирование репозитория

```bash
mkdir -p /opt && cd /opt
git clone git@github.com:alphaserver777/hashgraph.git mdrj
cd mdrj
git checkout protocol/hashgraph-consensus-alignment
```

Если у Zomro нет SSH-ключа к GitHub — клонируйте по HTTPS:
```bash
git clone https://github.com/alphaserver777/hashgraph.git mdrj
```

## 3. Развёртывание стенда

```bash
cd /opt/mdrj
./scripts/k3s/deploy.sh --replicas 5
```

Скрипт делает (см. [scripts/k3s/deploy.sh](../../scripts/k3s/deploy.sh)):
1. Создаёт k3d-кластер `mdrj` (1 server + 2 agent внутри Docker).
2. Собирает образ `mdrj-dag:demo` и импортирует в k3d (без push в registry).
3. Применяет манифесты из `deploy/k8s/` (namespace, ConfigMap, Service headless + NodePort, StatefulSet).
4. Генерирует `mdrj-secrets` с `hmac-key=$(openssl rand -hex 32)`.
5. Ждёт `rollout status` до Ready.

Проверка:
```bash
kubectl -n mdrj get pods -o wide
# NAME       READY   STATUS    RESTARTS   AGE   IP
# mdrj-0     1/1     Running   0          1m    10.42.1.10
# mdrj-1     1/1     Running   0          1m    10.42.1.11
# ...

kubectl -n mdrj get pvc       # data persistence
kubectl -n mdrj get svc       # mdrj-headless + mdrj-ui

curl http://localhost:30901/status   | jq
curl http://localhost:30901/peers    | jq     # 5 peers, все approved
curl http://localhost:30901/metrics  | jq
```

Дашборд: http://`<zomro-ip>`:30901/metrics/dashboard

## 4. Сценарии демонстрации

### 4.1. Нагрузочный тест

```bash
# 20 событий/сек, на все 5 узлов поровну, 60 секунд
HMAC=$(kubectl -n mdrj get secret mdrj-secrets -o jsonpath='{.data.hmac-key}' | base64 -d)
python3 scripts/k3s/load_gen.py \
  --pods localhost:30901 \
  --rate 20 \
  --duration 60 \
  --hmac-key "$HMAC"
```

После прогона:
- В дашборде видны графики `bytes_per_event`, `db_size_bytes`, `emit_to_consensus_latency_p95`.
- `/metrics/history?limit=200` отдаёт CSV-ready временной ряд для подстановки в `simulation.html`.

### 4.2. Chaos: выживание при падении узлов

```bash
# Убивает 1 случайный pod каждые 30 секунд, 5 раундов
./scripts/k3s/chaos.sh --interval 30 --rounds 5
```

Параллельно в другом терминале гоните `load_gen.py` — события не должны теряться. Проверка после завершения:
```bash
# event_count должен совпадать на всех узлах
for p in mdrj-0 mdrj-1 mdrj-2 mdrj-3 mdrj-4; do
  echo -n "$p: "
  kubectl -n mdrj exec "$p" -- curl -fsS http://localhost:9001/metrics | jq -r .event_count
done
```

Quorum 2/3 от 5 = 4. Кластер переживает потерю 1 узла без потери checkpoint-кворума.

### 4.3. Tamper detection (главное для дисс)

```bash
# 1. Создаём checkpoint вручную
HMAC=$(kubectl -n mdrj get secret mdrj-secrets -o jsonpath='{.data.hmac-key}' | base64 -d)
SIG=$(printf '{}' | openssl dgst -sha256 -hmac "$HMAC" | awk '{print $2}')
curl -X POST -H "Content-Type: application/json" -H "X-MDRJ-Sig: $SIG" \
  -d '{}' http://localhost:30901/checkpoint/propose | jq

# 2. Запустить tamper demo на одном узле
./scripts/k3s/tamper_demo.sh --pod mdrj-3
```

Ожидаемый результат: первый verify даёт `matches_merkle: true`, после прямой модификации payload в SQLite mdrj-3 второй verify возвращает `has_tamper_evidence: true`. **Это прямая демонстрация защиты от УБИ.124.**

## 5. Снятие метрик для дисс

```bash
# 24-часовой прогон (фоном)
nohup python3 scripts/k3s/load_gen.py \
  --pods localhost:30901 \
  --rate 5 \
  --duration 86400 \
  --hmac-key "$HMAC" \
  > /var/log/mdrj-load.log 2>&1 &

# По окончании — выгрузка истории
curl -s "http://localhost:30901/metrics/history?limit=5760" \
  | jq -r '.items[] | [.ts, .snapshot.event_count, .snapshot.db_size_bytes,
                       .snapshot.bytes_per_event, .snapshot.emit_to_consensus_latency_p95_ms]
                      | @csv' > /tmp/mdrj_metrics.csv

# Скачать на ноут
scp root@<zomro-ip>:/tmp/mdrj_metrics.csv ./
```

Этот CSV подставляется в `simulation.html` (или в построение графиков для дисс) как **эмпирический ground truth** для A4.

## 6. Очистка

```bash
# Остановить кластер (данные сохранятся в Docker volumes)
k3d cluster stop mdrj

# Полное удаление
k3d cluster delete mdrj
docker volume prune -f
```

## Что НЕ автоматизировано

- Подписи checkpoint требуют HMAC — `tamper_demo.sh` и `chaos.sh` вытаскивают ключ из k8s secret. Не запускать на production-кластере без TLS.
- Notifier (email/Telegram) выключен в дефолтном configmap. Включите через `kubectl edit cm mdrj-node-config` и `kubectl rollout restart sts/mdrj` если нужно демо уведомлений.
- Web UI auth (login/password) — `users_count == 0` в свежем кластере, доступ открыт. Чтобы продемонстрировать защиту:
  ```bash
  kubectl -n mdrj exec mdrj-0 -- python -m mdrj.cli users add \
    --username demo --role admin --password 'demo-pw' --config /etc/mdrj/node.yaml
  ```

## Открытые вопросы

- **Долгий прогон + retention.** В configmap `retention.max_age_days: 1` — для дисс достаточно. Для production эту цифру нужно согласовывать с законными требованиями к хранению.
- **NodePort 30901 публичный.** На production за reverse-proxy с TLS.
- **Persistent volumes в k3d.** Хранятся в Docker volumes на хосте; при `cluster delete` теряются. Если нужно сохранить — `--volume /opt/mdrj-data:/var/lib/rancher/k3s/storage` в `k3d cluster create`.
