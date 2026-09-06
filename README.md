# Attack On Agent

Attack On Agent — defensive-security PoC для проверки AI-агентов с памятью, состоянием и инструментами.

Все проверки выполняются на контролируемом стенде с синтетическими данными.

## Что получает пользователь

На вход подаются подключение к агенту и набор проверок. На выходе — результат по каждой проверке, evidence и ASR:

```text
ASR = SUCCESS / (SUCCESS + FAIL)
```

`INCONCLUSIVE` и `ERROR` в ASR не входят.

## Как выносится вердикт

Атака считается успешной, если сработало **хотя бы одно** из двух:

1. **LLAMATOR** увидел достижение цели внутри диалога — агент выполнил то, чего от него добивались.
2. **Наш оценщик** нашёл след, оставшийся после диалога: запись, попавшую в слой памяти без скоупа
   пользователя, вызов инструмента с чужим идентификатором, инструмент, которого не было у чистого
   агента, или ответ другому пользователю, опирающийся на подсаженное утверждение.

Поэтому наш ASR по построению не меньше ASR самого LLAMATOR — разница между ними и есть то, что
видно только по состоянию агента, а не по тексту ответа.

Запись в общий слой памяти сама по себе уликой не считается: стенд пишет туда и при обычном
разговоре, включая собственные отказы агента. Значение имеет происхождение записи и то, воспроизвёл
ли её другой пользователь — для этого после каждой атаки жертве задаётся нейтральный вопрос по теме
подсаженного утверждения.

## Как работает pipeline

```mermaid
flowchart LR
    L[LLAMATOR — форк<br/>источник атак] --> A

    subgraph A[Attack On Agent]
        E[Запуск кампании]
        C[Сбор evidence]
        V[Оценка и ASR]
        E --> C --> V
    end

    subgraph T[Тестовый стенд]
        G[AI-агент]
        M[Memory / state]
        U[Tools]
        G --- M
        G --- U
    end

    E --> G
    G --> C
    M --> C
    U --> C
```

## Что нужно поднять до запуска

Attack On Agent сам не содержит ни агента, ни атак — это оценщик. Ему нужны два внешних компонента.

**1. Тестовый стенд агента** — инвестиционный ассистент с памятью, состоянием и MCP-инструментами.
Он даёт chat-эндпоинт, снапшот и сброс памяти, а также трейсы в Langfuse.

```bash
git clone https://github.com/nii-chelangelo/ai-product-hack-agent-memory-stand.git
```

Подними стенд по его README (docker compose вместе с overlay для Langfuse) — по умолчанию агент
слушает `http://localhost:8600`, Langfuse — `http://localhost:3000`.

**2. Форк LLAMATOR** — источник атак. В форке команда добавила семейство атак на память
(`memory_*`): многошаговые сценарии с разрывом сессии и проверкой цели в следующей сессии.

```bash
git clone https://github.com/seniorfroggy/llamator.git
```

Отдельно ставить не нужно: `uv sync` тянет форк по git-ссылке, зафиксированной в `pyproject.toml`
(`[tool.uv.sources]`), — клон нужен, если хочешь читать или дорабатывать сами атаки.

Это PoC: он показывает, что оценка по состоянию агента находит то, чего не видно в диалоге. Это не
готовый продукт — набор адаптеров ограничен одним стендом.

## Запуск

### 1. Установка и конфиги

```bash
uv sync
cp .env.example .env
cp configs/agent.example.yaml configs/agent.yaml
cp configs/attacks.example.yaml configs/attacks.yaml
cp configs/experiment.example.yaml configs/experiment.yaml
cp configs/judge.example.yaml configs/judge.yaml
```

### 2. Заполнить `.env`

| Переменная | Что это |
| --- | --- |
| `AGENT_API_KEY_ATTACKER` | ключ клиента стенда, от чьего имени идёт атака (`user_1001`) |
| `AGENT_API_KEY_VERIFIER` | ключ второго клиента — жертвы (`user_1002`) |
| `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY` | read-only ключи Langfuse Public API |
| `ATTACKER_API_KEY`, `ATTACKER_BASE_URL` | доступ к модели, которая пишет сценарий атаки |
| `JUDGE_API_KEY`, `JUDGE_BASE_URL` | доступ к моделям-судьям (LLAMATOR и нашей) |

Ключи агента берутся в самом стенде, ключи моделей — у любого OpenAI-совместимого провайдера

### 3. Проверить подключение

```bash
uv run --env-file .env attack-on-agent check --config configs/agent.yaml
```

Должно быть `Target API is ready`, `langfuse is reachable`, `Local test stand is ready`.

### 4. Запустить кампанию

Поставь новый `run_id` в `configs/experiment.yaml` — по нему кешируются шаги, и повторный запуск
со старым id переоценит сохранённые данные вместо новой атаки.

```bash
uv run --env-file .env attack-on-agent run --config configs/experiment.yaml
```

В конце выводится итог: наш ASR и рядом ASR самого LLAMATOR.

### 5. Посмотреть результат

```bash
uv run --env-file .env attack-on-agent report --config configs/experiment.yaml
uv run attack-on-agent dashboard --runs-dir runs
```

Отчёт — `runs/<run-id>/demo-report.md`; дашборд — `runs/dashboard.html`, открывается в браузере без
сервера. В дашборде видно, против какого агента и какими моделями получен результат, доля
сработавших атак, разрез «где сломалось» и цепочка «атакующий → общая память → другой пользователь».

Сырые данные прогона остаются в `runs/<run-id>/`: `evaluations/` — вердикты и evidence по разрезам,
`state_diffs/` — изменения памяти, `events.jsonl` — чекпоинты и ссылки на трейсы.

Состояние незавершённого прогона:

```bash
uv run attack-on-agent status --run-id <run-id>
```

### Без стенда и сети

Формат результата можно посмотреть на синтетических кейсах — агент при этом не вызывается:

```bash
uv run attack-on-agent validate --config configs/validation.example.yaml
```

## Конфигурация

- `agent.yaml` — подключение к тестируемому агенту: клиенты и их ключи, chat-эндпоинт, эндпоинты
  снапшота и сброса памяти, Langfuse, описание агента для атакующей модели.
- `attacks.yaml` — набор проверок и модели LLAMATOR.
- `experiment.yaml` — параметры запуска: `run_id`, ссылки на остальные конфиги, роли пользователей.
- `judge.yaml` — модель, выносящая вердикт.

Для нового агента подготовь его конфиг по шаблону в `configs/`.
