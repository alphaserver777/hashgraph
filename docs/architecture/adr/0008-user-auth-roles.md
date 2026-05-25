# ADR-0008: Аутентификация пользователей Web UI и role-gating

## Статус
Принято (этап 5 прототипа). Этап завершает «человеческий» периметр безопасности узла, дополняя HMAC (ADR-0002) для inter-node трафика.

## Контекст
До этого решения HTTP API узла имел только HMAC-аутентификацию (ADR-0002), которая защищала state-changing endpoints от посторонних запросов в общей сети. Но HMAC требует **общего секрета** — для оператора, заходящего в `/viz` или `/metrics/dashboard` через браузер, держать `hmac_key` и подписывать каждый запрос неудобно.

Также:
- ТЗ диссертации требует разделение ролей: «обычный агент (только отправка событий)» vs «агент + локальный просмотр (для администратора распределённого реестра)».
- Demo-симуляция и `/viz/clear` должны быть доступны только администратору, не любому пользователю с доступом к /viz.
- Нужен audit trail: кто и когда вошёл в систему.

## Решение

### Хранение пользователей (`mdrj/auth.py`, `mdrj/storage.py`)
- Новая таблица `users(username PK, password_hash, role, created_at)`.
- Пароли хешируются через **stdlib `hashlib.scrypt`** с параметрами n=2^14, r=8, p=1, salt=16 байт. Это сильнее PBKDF2 и не требует внешних зависимостей (argon2-cffi). Self-contained формат: `scrypt$N$r$p$salt_b64$hash_b64`.
- Роли:
  - **`viewer`** — может читать `/dag`, `/metrics`, `/peers`, `/incidents`, `/viz`. **Не может** делать никаких write-операций.
  - **`admin`** — полный доступ, включая управление peers, очистку DAG, симуляцию, добавление пользователей.

### Сессии (`SessionStore`)
- In-memory `dict[token → SessionRecord]`. После рестарта узла все сессии теряются — пользователи логинятся заново.
- TTL по умолчанию 8 часов.
- Token = `secrets.token_urlsafe(32)`.
- Cookie name `mdrj_session`, HttpOnly + SameSite=Lax.

### Middleware (`session_auth_middleware` в api.py)
1. Если в БД нет пользователей → **open-access mode**. Это backward-compat для существующих демо-конфигов: оператор может работать сразу, без обязательного создания admin-пользователя.
2. Если есть хотя бы один пользователь → все endpoints (кроме `AUTH_PUBLIC_PATHS`) требуют сессию.
3. Без сессии:
   - `Accept: text/html` + GET → 302 redirect на `/auth/login`.
   - JSON/CLI клиент → 401.
4. С сессией: проверка роли:
   - Viewer + write-метод → 403.
   - Viewer + GET, путь не в `VIEWER_READ_PATHS` → 403.
   - Admin → разрешено всё.
5. `AUTH_PUBLIC_PATHS` всегда открыты: `/auth/login`, `/auth/logout`, `/status` (нужно для k3s liveness probe), `/event/batch` (inter-node gossip, защищён HMAC).

### Взаимодействие с HMAC middleware
Middleware-цепочка: `session_auth_middleware` (внешний) → `hmac_auth_middleware` (внутренний).
- Если запрос имеет **валидную сессию**, HMAC middleware его пропускает. UI-пользователь не обязан подписывать каждый запрос.
- Если сессии нет, HMAC middleware применяет HMAC-проверку как раньше. Это путь для:
  - inter-node gossip (`/event/batch`, `/checkpoint/propose`),
  - CLI команд (которые шлют запросы с HMAC-подписью).

### HTTP API
- `GET /auth/login` — HTML страница с формой.
- `POST /auth/login {username, password}` → 200 с cookie или 401.
- `POST /auth/logout` → cleared cookie.
- `GET /auth/me` → `{username, role, expires_at}` либо 401.
- `GET /users`, `POST /users/add`, `POST /users/remove` — управление пользователями (только admin).

### CLI (`mdrj users …`)
Работает **оффлайн** напрямую с SQLite, не через HTTP. Это намеренно — позволяет добавить первого admin до запуска узла или восстановить доступ когда сеть недоступна.
- `mdrj users add --username X --role admin --config node.yaml` — пароль запрашивается интерактивно.
- `mdrj users list --config node.yaml`.
- `mdrj users remove --username X --config node.yaml`.

## Последствия

**Положительные:**
- **Двухслойная защита**: HMAC для machine-to-machine, session для human-to-machine. Каждый слой соответствует своему классу клиента.
- **Open-access по умолчанию**: новый деплой работает сразу, не требуя обязательного `users add` — оператор сам решает, когда включать auth.
- **Простая ролевая модель** (viewer/admin) маппится на ТЗ диссертации напрямую. Нет over-engineering.
- **Сессии в памяти**: zero persistent state, никаких leak'ов токенов при рестарте, никаких RBAC-кэшей.
- **CLI offline-доступ к users**: восстановление admin не требует поднимать сеть.

**Отрицательные / ограничения:**
- **Сессии теряются при рестарте узла.** Это намеренный trade-off простоты против UX. Пользователи перелогиниваются. В production стоило бы хранить session token (либо JWT с node-secret, либо persistent table).
- **Нет «remember me» / refresh tokens.** Session TTL фиксированный 8 часов. После истечения — login снова.
- **Открытый login без rate-limit.** Атаки brute force на /auth/login не ограничены. scrypt-хеш делает каждую попытку дорогой (~50ms), но в production нужны explicit rate limit / fail2ban.
- **Только два уровня роли.** Нет тонкой грануляции «approve peers но не clear DAG». Если потребуется — расширяется через `permissions` поле в users.
- **HTML login очень простой.** Это не дизайн-проект; форма работает, но без branding и доступности.
- **Cookie не флаг Secure.** В k3s за reverse-proxy с HTTPS нужно вручную проксировать `X-Forwarded-Proto` и добавлять `secure=True` на cookie. Сейчас прототип работает по HTTP без TLS.

## Связь с дисс-демонстрацией
В k3s-демо (этап k3s deployment):
- Init-job создаёт admin-пользователя через CLI в каждом pod-е.
- Дашборд /metrics/dashboard теперь защищён — это правильный workflow для защиты.
- ТЗ-требование «обычный агент vs агент с локальным просмотром» реализовано через роли.

## См. также
- [ADR-0002](0002-hmac-api-auth.md) — HMAC для inter-node / CLI auth. Дополняется session middleware.
- [ADR-0007](0007-peer-discovery-approval.md) — approve_peer работает только под admin-сессией (POST → требует write-роль).
- [docs/devplan/devplan.md](../../devplan/devplan.md) этап 2.2 — этим решением частично закрыт (отделение UI логики от backend ядра — задача отдельная).
