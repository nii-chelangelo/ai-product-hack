# Attack On Agent

Attack On Agent — defensive-security PoC для проверки AI-агентов с памятью, состоянием и инструментами.

Все проверки выполняются на контролируемом стенде с синтетическими данными.

## Что получает пользователь

На вход подаются подключение к агенту и набор проверок. На выходе — результат по каждой проверке, evidence и ASR:

```text
ASR = SUCCESS / (SUCCESS + FAIL)
```

`INCONCLUSIVE` и `ERROR` в ASR не входят.

## Быстрый старт

```bash
uv sync
cp .env.example .env
cp configs/agent.example.yaml configs/agent.yaml
cp configs/attacks.example.yaml configs/attacks.yaml
cp configs/experiment.example.yaml configs/experiment.yaml
```

Заполни `.env`, настрой `agent.yaml`, выбери проверки в `attacks.yaml` и укажи новый `run_id` в `experiment.yaml`. При необходимости подключи judge через `configs/judge.yaml`.

Проверь стенд и запусти кампанию:

```bash
uv run --env-file .env attack-on-agent check --config configs/agent.yaml
uv run --env-file .env attack-on-agent run --config configs/experiment.yaml
```

Результаты лежат в `runs/<run-id>/`: итог проверки, evidence и данные для последующего анализа.

## Конфигурация

- `agent.yaml` — подключение к тестируемому агенту.
- `attacks.yaml` — набор проверок.
- `experiment.yaml` — параметры запуска.

Для нового агента подготовь его конфиг по шаблону в `configs/`.
