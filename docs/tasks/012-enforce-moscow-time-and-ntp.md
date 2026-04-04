# Task: Зафиксировать NTP-Синхронизацию И Московское Время На Узлах

## Проверка Контекста Перед Работой
- [x] Перечитан `docs/WORKFLOW.md`
- [x] Перечитан `docs/constitution.md`
- [x] Перечитан `docs/architecture/architecture.md`
- [x] Перечитан `docs/architecture/invariants.md`
- [x] Перечитан `docs/devplan/devplan.md`
- [x] Перечитаны релевантные `docs/tasks/*.md`
- [x] Перечитан `docs/ops/DEPLOYMENT.md`

## Status
`done`

## Контекст
Внешний двухузловой стенд уже поднят на `Germany` и `Zomro`. Для эксплуатационной предсказуемости и понятной операторской картины нужно явно зафиксировать единый режим времени на всех узлах: синхронизация часов через NTP и локальная временная зона `Europe/Moscow`.

## Цель
Сделать время на всех узлах внешнего стенда управляемым и одинаково интерпретируемым: системные часы синхронизируются по NTP, а локальное операционное представление времени использует московскую временную зону.

## Scope
- Зафиксировать правило времени в документации проекта.
- Явно проверить и при необходимости включить NTP на `Germany` и `Zomro`.
- Явно проверить и при необходимости установить `Europe/Moscow` на `Germany` и `Zomro`.
- Зафиксировать verification по стенду.

## Ограничения
- Не менять семантику `consensus_ts` или внутреннего порядка событий.
- Не вводить отдельный time service или кастомный clock-layer в приложении.
- Не смешивать задачу с TLS, discovery или расширением ingestion.

## Текущее состояние
- Узлы уже используют epoch/ISO-временные отметки в runtime и ingestion.
- Для внешнего стенда пока не было отдельного documented-правила про timezone и NTP.
- На практике `Germany` и `Zomro` уже находятся в `Europe/Moscow` и сообщают `NTPSynchronized=yes`, но это нужно сделать явной частью эксплуатационного контура.

## Предлагаемое изменение
- Добавить в проектное правило:
  - все внешние узлы обязаны иметь включённую NTP-синхронизацию;
  - для операционного времени и журналов на стенде используется `Europe/Moscow`.
- Отразить это в `constitution`, `architecture`, `DEPLOYMENT` и `devplan`.
- На `Germany` и `Zomro` явно применить:
  - `timedatectl set-timezone Europe/Moscow`
  - `timedatectl set-ntp true`

## Затронутые области
- Документация:
  - эта task spec
  - `docs/constitution.md`
  - `docs/architecture/invariants.md`
  - `docs/ops/DEPLOYMENT.md`
  - `docs/devplan/devplan.md`
- Deploy / Infra:
  - `Germany`
  - `Zomro`

## Acceptance Criteria
- [x] В документации явно зафиксировано требование NTP + `Europe/Moscow` для внешних узлов.
- [x] На `Germany` включён NTP и установлена временная зона `Europe/Moscow`.
- [x] На `Zomro` включён NTP и установлена временная зона `Europe/Moscow`.
- [x] Verification с `timedatectl` зафиксирована по обоим узлам.

## Verification
- [x] `ssh Germany 'timedatectl set-timezone Europe/Moscow && timedatectl set-ntp true && timedatectl show -p Timezone -p NTP -p NTPSynchronized -p SystemClockSynchronized'`
- [x] `ssh Zomro 'timedatectl set-timezone Europe/Moscow && timedatectl set-ntp true && timedatectl show -p Timezone -p NTP -p NTPSynchronized -p SystemClockSynchronized'`
- [x] Проверка документации на согласованность с фактическим стендом

## Rollback / Safety
Откат возможен через возврат timezone на предыдущую и выключение `set-ntp`, но для стенда это нецелесообразно без отдельной причины. Задача не меняет данные реестра и не требует миграций.

## Заметки
- NTP сам по себе не означает “московский источник времени”; источник синхронизации остаётся системным, а `Europe/Moscow` задаёт локальное операционное представление времени.
- Для runtime-порядка событий source of truth остаются временные метки и логика `consensus_ts`, а не строковое отображение timezone.
- Фактическая проверка выполнена `2026-04-04` на:
  - `Germany`
  - `Zomro`
- На обоих узлах подтверждено:
  - `Timezone=Europe/Moscow`
  - `NTP=yes`
  - `NTPSynchronized=yes`
