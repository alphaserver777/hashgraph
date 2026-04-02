# Эксплуатационные Заметки

## Текущие Режимы Запуска
- Локальный процесс:
  - `python -m venv .venv`
  - `source .venv/bin/activate`
  - `pip install -e .`
  - `python -m mdrj.cli node --config configs/node.example.yaml`
- Тесты:
  - `pytest`
- Docker-кластер:
  - `docker compose up --build -d node1 node2 node3`
- Базовый demo-сценарий:
  - `docker compose --profile demo-baseline up demo-baseline`

## Эксплуатационные Допущения
- Каждый узел использует собственный SQLite-файл.
- Demo-конфиги в основном статичны, а топология пиров обычно задаётся заранее.
- Сценарии partition/heal инициируются оператором через вспомогательные скрипты и сетевые правила.

## Пробелы
- В репозитории пока не описан CI pipeline.
- Для SQLite-файлов не определена стратегия миграций и резервного копирования.
- В проектных артефактах не зафиксирована стандартная команда lint/format.
