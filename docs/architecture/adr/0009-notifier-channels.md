# ADR-0009: Notifier для критичных событий ИБ

## Статус
Принято (этап 6 прототипа). Завершает «выходную» цепь узла: коллекторы → DAG → consensus → notification оператору.

## Контекст
До этого решения узел только хранил события и реплицировал их по сети — оператор узнавал о критическом инциденте, только если зашёл в `/viz` или явно опрашивал `/dag`. ТЗ дисс требует мгновенное уведомление при высококритичных событиях, включая способы доставки: popup, звук, email, Telegram (опционально).

## Решение

### Архитектура (`mdrj/notifier.py`)
- `NotifierEngine` — per-node диспатчер. Подписан на новые события через прямой вызов из `Node.emit_event` после успешного `_persist_envelope`.
- `BaseChannel` — контракт `async send(notification) -> bool`. Каналы независимы.
- Конкретные каналы:
  - **`EmailChannel`** — stdlib `smtplib` через `asyncio.to_thread`. STARTTLS + login, опционально без TLS. Никаких новых зависимостей.
  - **`TelegramChannel`** — aiohttp POST на api.telegram.org. Поддерживает несколько chat_ids в одной конфигурации.
  - **Popup + audio** — НЕ отдельный канал, доставляется через **существующий** `/viz/stream` SSE поток (ADR-0004). Frontend в `/viz` подписан на новые события и сам показывает popup + Web Audio API beep при `cls == "A"`.

### Конфигурация (`NotifierConfig` в `mdrj/config.py`)
```yaml
notifier:
  enabled: true
  trigger_classes: ["A"]   # only critical
  email:
    enabled: true
    smtp_host: smtp.example.com
    smtp_port: 587
    smtp_user: alerts@example.com
    smtp_password: ${SMTP_PASS}
    use_tls: true
    from_addr: alerts@example.com
    to_addrs: ["soc@example.com"]
  telegram:
    enabled: true
    bot_token: ${TELEGRAM_BOT_TOKEN}
    chat_ids: ["-100123456789"]
```

### Lifecycle
1. `Node.__init__` создаёт `NotifierEngine` с конфигом из `config.notifier`.
2. После `emit_event` → `_persist_envelope`, если событие класса A (или другого, указанного в `trigger_classes`), запускается фоновая задача `Node._notify_event(event)`.
3. `NotifierEngine.dispatch(notification)` параллельно отправляет в каждый enabled канал; результат `Dict[channel_name → bool]`.
4. Каналы записывают `last_error` для диагностики, но не блокируют друг друга при отказе.
5. `GET /notifier/status` отдаёт `{enabled, trigger_classes, channels: [{name, last_error}], sent_count, failed_count}` — viewer-роль может видеть.

### Что НЕ реализовано в этом этапе
- **Подписки per-user.** План упоминал `notifier_subscriptions` таблицу. Сейчас все каналы получают **все** срабатывания одинаково — это per-node глобальная конфигурация. Доработка требует UI и связки с users — отложено.
- **Slack / PagerDuty / webhook.** Простое расширение через новый `BaseChannel`-подкласс.
- **Throttling / deduplication.** Сейчас каждое событие класса A инициирует уведомление. При burst-сценарии (10 failed_login_burst за минуту) это спам. Production-вариант должен агрегировать.

## Последствия

**Положительные:**
- **Мгновенное уведомление** оператора при критическом инциденте. Это прямо отвечает ТЗ диссертации.
- **Каналы независимы** — отказ Telegram не блокирует email и наоборот.
- **Никаких новых runtime-зависимостей** (smtplib stdlib, aiohttp уже был).
- **Popup/звук бесплатно**: SSE уже доставляет события в `/viz`; нужно только добавить UI-handler в frontend.
- **Тестируемо без сети**: `session_factory` параметр в `TelegramChannel` позволяет mock-инжектить aiohttp.ClientSession; email через `_send_blocking` мокается через monkey-patch на `smtplib.SMTP`.

**Отрицательные / ограничения:**
- **При большом потоке A-событий нет throttling.** Один failed_login_burst → один email/Telegram per узел; при 5 узлах в кластере оператор получит 5 копий одного события. Это требует кластерного дедупликации либо локального cooldown.
- **Notifier per-node.** Если узлы видят разные подмножества событий до consensus (split-brain), уведомления тоже разные. После consensus всё совпадёт, но пользователь может получить «ложный» алерт о событии, которое потом будет отвергнуто. Это допустимо для прототипа.
- **Email пароль в открытом виде в config.** Production должен использовать env-переменные через `${SMTP_PASS}`-механизм (уже поддерживается в `_expand_env_vars`).
- **Telegram bot_token не ротируется.** При утечке надо вручную revoke в BotFather и обновить config.
- **Email-канал использует stdlib smtplib через to_thread.** Это блокирует один thread пула. При больших объёмах нужен aiosmtplib.

## Связь с дисс-демонстрацией
В k3s-демо при kubectl exec mdrj-2 эмиссии события `virus` оператор должен получить:
1. Popup в браузере + beep (через SSE на `/viz`).
2. Email на soc@... (если SMTP настроен в ConfigMap).
3. Telegram уведомление (если bot_token в Secret).

Это закрывает три из четырёх каналов ТЗ; popup+звук = один canal (SSE), email и Telegram — отдельные.

## См. также
- [ADR-0004](0004-resource-metrics-dashboard.md) — SSE /viz/stream используется как popup-канал.
- [ADR-0001](0001-event-kind-contract.md) — event_kind в payload используется в текстовом теле уведомления.
- [docs/devplan/devplan.md](../../devplan/devplan.md) этап 4 закрыт.
- Открытые вопросы: throttling и кластерный dedup, persistent subscriptions per-user.
