# Task: Перевести Панель Инцидентов На Роли Узлов `node/responder`

## Проверка Контекста Перед Работой
- [x] Перечитан `docs/WORKFLOW.md`
- [x] Перечитан `docs/constitution.md`
- [x] Перечитан `docs/architecture/architecture.md`
- [x] Перечитан `docs/architecture/invariants.md`
- [x] Перечитан `docs/devplan/devplan.md`
- [x] Перечитаны релевантные `docs/tasks/*.md`
- [x] Перечитан `docs/ops/DEPLOYMENT.md`

## Status
`in-progress`

## Контекст
Исторически вкладка `Инциденты` включалась по жёсткому `node_id`, а поле `profile.role` в интерфейсе показывало старые profile-значения вроде `light/medium/relay`. После появления локального SQLite peer-registry это стало слабым местом: роль не управлялась из operator UI и не была частью сохранённого реестра участников сети.

## Цель
Сделать две явные роли узла:
- `node` — обычный участник сети;
- `responder` — участник сети с operator UI для обработки инцидентов.

Вкладка `Инциденты` должна включаться по роли текущего узла, а не по хардкоду.

## Scope
- Добавить поле `role` в peer-registry.
- Хранить роль текущего узла в том же локальном реестре.
- Перевести `/status` и `/peers` на role-based модель.
- Добавить выбор роли в разделе `Участники сети`.
- Убрать включение incident-workbench по `node_id`.
- Нормализовать устаревшие значения `light/medium/relay` в `node`.

## Ограничения
- В первой версии роль влияет только на UI/operator-level.
- Роль не должна менять gossip, консенсус или сетевую политику.
- Роли удалённых узлов остаются локальной operator-моделью конкретного узла, а не кластерным consensus fact.
- Self-entry текущего узла нельзя удалять или исключать из сети через UI.

## Текущее состояние
- Панель инцидентов привязана к одному `node_id`.
- Peer-registry уже хранится в SQLite, но без роли.
- UI участников сети умеет менять `enabled` и `note`, но не роль.
- `/status.profile.role` ещё опирается на конфиг.

## Предлагаемое изменение
- Ввести `peers.role` со значениями `node/responder`.
- При bootstrap создавать self-entry текущего узла в peer-registry.
- Возвращать effective role текущего узла через `/status.profile.role`.
- Показывать пункт `Инциденты` только для роли `responder`.
- В таблице участников сети дать менять роль и для текущего узла, и для удалённых участников.
- Текущее поле `Роль` в карточке узла сделать интерактивным переходом к управлению участниками сети.

## Acceptance Criteria
- [ ] В `SQLite peers` есть поле `role`.
- [ ] Для существующих записей без роли проставляется `node`.
- [ ] Текущий узел имеет self-entry в peer-registry.
- [ ] `/peers` возвращает `role` для каждой записи.
- [ ] `/status.profile.role` отражает effective role текущего узла из peer-registry.
- [ ] При роли `responder` видна вкладка `Инциденты`.
- [ ] При роли `node` вкладка `Инциденты` скрыта, но данные инцидентов не удаляются.
- [ ] В таблице `Участники сети` роль можно изменить без перезагрузки страницы.
- [ ] Старые конфиги с `light/medium/relay` не падают и нормализуются в `node`.

## Verification
- [ ] `python -m py_compile mdrj/api.py mdrj/node.py mdrj/storage.py mdrj/config.py mdrj/models.py`
- [ ] Проверить, что self-entry текущего узла видна в реестре и не удаляется.
- [ ] Проверить смену роли `node -> responder -> node` из `/viz`.
- [ ] Проверить, что `/status` и `/peers` согласованы по роли текущего узла.
- [ ] Проверить, что demo-контур `node1/node2/node3` снова показывает incident-workbench только на узле с ролью `responder`.

## Rollback / Safety
Rollback должен возвращать систему к старому включению incident-workbench, но без повреждения SQLite peer-registry. При откате допустимо игнорировать `peers.role`, если код снова не использует это поле.

## Заметки
- Для demo-кластера разумный default: `node1 = responder`, `node2/node3 = node`.
- Для универсального Linux-контейнера default role — `node`.
