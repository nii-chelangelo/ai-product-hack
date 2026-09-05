# Attack On Agent

Attack On Agent — defensive-security PoC для проверки AI-агентов с памятью, состоянием и инструментами. Он выполняет многошаговые сценарии, собирает evidence и показывает ASR — долю подтверждённо успешных атак.

Все эксперименты выполняются на контролируемом стенде с синтетическими данными.

## Что получает пользователь

Для каждой кампании пользователь получает:

- итог `SUCCESS`, `FAIL`, `INCONCLUSIVE` или `ERROR` для каждого сценария;
- ASR: `SUCCESS / (SUCCESS + FAIL)`;
- evidence по памяти, состоянию, ответам и tool calls;
- список точек компрометации для успешных сценариев.

`INCONCLUSIVE` и `ERROR` не искажают ASR: первый означает недостаток evidence, второй — технически незавершённый run.

## Подготовка

```bash
uv sync
cp .env.example .env
cp configs/agent.example.yaml configs/agent.yaml
```

Заполни в `.env` ключ агента и read-only ключи Langfuse.

## Пользовательский путь

1. Подключить тестируемого агента к Langfuse и передавать в trace `user_id`, `session_id`, имя инструмента, аргументы, output и ошибки.
2. Предоставить Target Adapter: API для chat, финализации сессии, read-only snapshot memory/state и reset состояния.
3. Создать `configs/<agent>.yaml` с endpoint-ами, пользователями и именами переменных окружения для ключей.
4. Создать `configs/attacks.yaml`: выбрать атаки, пользователей и измеряемые разрезы.
5. Проверить подключение:

   ```bash
   uv run --env-file .env attack-on-agent check --config configs/agent.yaml
   ```

6. Выполнять шаги проверки через CLI и изучать evidence в `runs/<run-id>/`.

## Контракт подключения агента

Target Adapter — единственное место, которое зависит от архитектуры агента. Он не меняет security policy и правила evaluator, а переводит контракт Attack On Agent в API конкретного target-а.

| Возможность | Что должен предоставить adapter |
| --- | --- |
| Chat | Отправить сообщение от именованного пользователя в явную сессию и вернуть итоговый ответ. |
| Finalize | Сохранить сессию в persistent memory или вызвать эквивалентный lifecycle. |
| Snapshot | Вернуть read-only user-scoped снимок memory/state для сессии. |
| Reset | Очистить состояние, созданное run, перед независимой кампанией. |
| Langfuse | Записать trace с user/session correlation и tool evidence. |

Шаблон: [`configs/agent.example.yaml`](configs/agent.example.yaml).

## Конфигурация атак

Campaign не зависит от target-а. Он задаёт набор атак, способ отбора и разрезы оценки. Например:

```yaml
attacks:
  mode: include
  ids: [memory-persistence, tool-injection]
```

Или запустить все доступные атаки:

```yaml
attacks:
  mode: all
```

`all` и `include` взаимоисключающие: у `all` нет `ids`, у `include` список обязателен. Полный шаблон: [`configs/attacks.example.yaml`](configs/attacks.example.yaml).

## Данные эксперимента

`runs/<run-id>/` содержит источник истины: `state.json`, `events.jsonl`, state diff и evaluation JSON. Они нужны для воспроизведения результатов и анализа evidence.
