# ADR-0007: Peer discovery (mDNS + Kubernetes DNS) и approval workflow

## Статус
Принято (этап 4 прототипа). Готовит почву для k3s-демонстрации (5–10 узлов) с автоматической сетевой топологией и операторским контролем над её составом.

## Контекст
До этого решения у узла были два способа узнать о peer-ах: статический список в YAML-конфиге (`peers: [...]`) и ручной POST на `/peers/register`. Это:
- Не масштабируется на 10+ узлов в k3s — каждый pod пришлось бы хардкодить.
- Не предусматривает контроль над тем, кто присоединяется. Любой узел с правильным `security.hmac_key` мог стать частью кластера.
- Не различает доверенные (manually added) и обнаруженные (auto-discovered) узлы.

Для дисс-демонстрации требуется:
1. **k3s-friendly discovery** — узлы должны сами находить друг друга через headless Service.
2. **LAN-friendly discovery** — для bare-metal лабораторных стендов через mDNS.
3. **Operator gate** — автоматически обнаруженные узлы должны ждать явного approval, иначе вектор атаки «подкинуть узел в сеть» становится тривиальным.

## Решение

### Approval status
В `PeerInfo` и таблице `peers` добавлено поле `approval_status` ∈ {`pending`, `approved`, `rejected`}.
- Дефолт `approved` для backward-compat: pre-Stage-4 записи остаются работоспособными после migration через `ALTER TABLE`.
- Manually registered peers (source=`ui`, source=`config`) → `approved` сразу.
- Auto-discovered peers (source=`mdns`, source=`k8s`) → `pending`.
- Только `approved`-узлы попадают в **active gossip set** (`Node.list_peers()`). `pending` и `rejected` видны в registry (`Node.list_peer_registry()`), но gossip с ними не идёт.
- `Node.approve_peer(address)` / `Node.reject_peer(address)` управляют статусом. HTTP: `POST /peers/approve`, `POST /peers/reject`.

### Discovery backends (`mdrj/discovery.py`)
Базовый класс `BaseDiscovery` определяет контракт: фоновый async-loop вызывает `_discover_once()` каждые `poll_interval_sec`, дедуплицирует находки и вызывает callback `on_peer(address, node_id, source)`.

**`KubernetesDNSDiscovery`** (для k3s/k8s):
- Конфиг: `discovery.mode=k8s`, `discovery.k8s_service=mdrj-headless.mdrj.svc.cluster.local`, `discovery.k8s_target_port=9001`.
- Реализация: `socket.getaddrinfo(service)` через `asyncio.to_thread`. Headless service в k8s возвращает A-record для каждого pod, что даёт список всех живых backends.
- Дополнительных зависимостей нет — только stdlib.
- Это **естественный** способ discovery в Kubernetes, проще и надёжнее mDNS.

**`MDNSDiscovery`** (для bare-metal LAN):
- Конфиг: `discovery.mode=mdns`, `discovery.advertise_port=9001`.
- Реализация: `zeroconf` package. Узел регистрирует сервис `_mdrj._tcp.local.` с TXT-record `node_id=…`, и слушает других через `ServiceBrowser`.
- Если `zeroconf` не установлен — backend graceful degrades to no-op с warning. Зависимость опциональная.

### Discovery callback flow
1. Backend обнаружил peer (mDNS service notification или k8s DNS A-record).
2. Если peer уже есть в registry (любой approval status) — игнор.
3. Иначе вызывается `Node._on_discovered_peer(address, node_id, source)`.
4. Метод вызывает `register_peer` с `approval_status=pending` и source=`mdns|k8s`.
5. Peer **не получает gossip** до approve.

### НЕ реализовано в Этапе 4
- **NAT traversal** не реализован. План упоминал bootstrap-peer + long-polling, но это отложено в пользу прямого k3s-варианта, где NAT не проблема (узлы в одной cluster network).
- **mDNS-зависимость zeroconf не добавлена в pyproject.toml.** Это сознательно: для основной k3s-демонстрации используется k8s discovery, а mDNS пригодится позже. Установка опциональная (`pip install zeroconf`).

## Последствия

**Положительные:**
- **k3s готов:** узлы автоматически находят друг друга при `replicas: 10`, не требуется ConfigMap с peer-listом.
- **Security gate:** новые узлы не получают gossip-трафика до явного operator approve. Защищает от атаки «подкинуть узел и собирать события».
- **Backward-compat:** существующие конфиги (3 docker-узла, peers: ...) продолжают работать без изменений — все они `source=config|ui` и сразу `approved`.
- **mDNS-fallback** для лабораторных стендов с bare-metal сетью (когда k3s нет).
- **Audit trail:** в registry видно, как был обнаружен каждый peer (`source` + `approval_status`).

**Отрицательные / ограничения:**
- **Approval по умолчанию открыт для пре-Stage-4 записей.** Это правильно для миграции, но если узел уже был в registry — изменение его approval требует явного API-вызова.
- **Никаких подписей в discovery announcement.** Зловредный узел может присвоить себе любой `node_id` в mDNS TXT-record. Но это не проблема, потому что (а) peer всё равно `pending`, (б) при первом gossip-запросе HMAC-проверка (ADR-0002) отсечёт. Discovery — лишь способ узнать о соседях, не аутентификация.
- **mDNS только IPv4.** `Zeroconf(ip_version=IPVersion.V4Only)` для простоты. IPv6 потребует доработки.
- **Kubernetes discovery не различает self.** Backend сам отфильтровывает свой адрес через `self_address` сравнение строк — это требует точного совпадения формата (ip:port). В k3s это работает, потому что headless service отдаёт pod IP, и узел знает свой pod IP через downward API (env var).
- **Approval / reject — необратимы только для текущего processing.** Если `rejected` peer повторно попадает в mDNS discovery — обнаружение игнорируется (peer уже в registry). Это **правильно** — rejected peer не должен «вернуться» автоматически. Восстановить можно только через `/peers/approve` явно.

## Связь с дисс-демонстрацией
Для k3s-демо с 5+ узлами этот ADR — критический. StatefulSet манифест:
```yaml
spec:
  replicas: 5
  serviceName: mdrj-headless
  template:
    spec:
      containers:
        - name: mdrj
          env:
            - name: MDRJ_DISCOVERY_MODE
              value: "k8s"
            - name: MDRJ_DISCOVERY_K8S_SERVICE
              value: "mdrj-headless.default.svc.cluster.local"
```
Поскольку StatefulSet даёт стабильные имена (`mdrj-0`, `mdrj-1`…), оператор может pre-approve их через init-job или `mdrj peers approve` в startup-hook, и кластер начинает gossip немедленно.

## См. также
- [ADR-0002](0002-hmac-api-auth.md) — HMAC API auth обеспечивает аутентификацию **трафика** между узлами; discovery даёт **обнаружение**. Это разные слои.
- [docs/devplan/devplan.md](../../devplan/devplan.md) этап 2.5 «Управляемый реестр участников сети» — этим решением закрыт.
- Открытый вопрос (NAT traversal через bootstrap-peer) — отложен до фазы 6+, когда понадобится мультикластерная конфигурация.
