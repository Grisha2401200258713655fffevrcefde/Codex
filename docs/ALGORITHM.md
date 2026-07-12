# Алгоритм LynxBrain

LynxBrain строит цикл принятия решений:

```text
сбор → личная норма → аномалии → корреляция → приоритет
     → безопасное действие → проверка → обновление вероятности
```

## Личная норма

Для каждой пары `host + metric` хранится история. Вместо среднего используется медиана, а вместо стандартного отклонения — MAD:

```text
MAD = median(|xᵢ − median(x)|)
score = |current − median| / max(1.4826 × MAD, fallback_scale)
```

Значение `score ≥ 3` считается необычным. Пока не накоплено `minimum_baseline_samples`, работают жёсткие правила безопасности.

## Корреляция

Несколько симптомов объединяются в одну вероятную причину:

- заполненный диск и упавшие контейнеры → `disk_pressure`;
- OOM и высокая RAM → `memory_pressure`;
- Docker down и несколько контейнеров down → `docker_engine_down`;
- TCP доступен, но SSH нет → `ssh_unavailable`;
- HTTP check down при работающем Docker → `http_service_failure`.

## Выбор действия

```text
score = success_probability × expected_effect
      − risk
      − resource_cost
      − repetition_penalty
```

Вероятность успеха обучается с бета-распределением:

```text
P(success) = alpha / (alpha + beta)
```

Начало: `alpha=1`, `beta=1`. Успех увеличивает `alpha`, неудача — `beta`.

## Контур безопасности

- `auto_remediation=false` по умолчанию;
- только точное совпадение с `allowed_actions`;
- проверка безопасного имени цели;
- уровни риска и cooldown;
- SSH BatchMode без паролей;
- API-токен для POST;
- проверка состояния после действия;
- никаких автоматических reboot, удаления данных и изменения сети.
