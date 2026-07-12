# 🐾 LynxBrain

**Лёгкий автономный мозг домашней лаборатории для слабого сервера.**

LynxBrain собирает состояние Ubuntu/Debian-узлов по SSH, запоминает личную норму каждого сервера, обнаруживает аномалии, связывает симптомы с вероятной первопричиной и предлагает безопасное действие. При явном разрешении он может выполнить allowlisted-действие, проверить результат и обновить свою оценку вероятности успеха.

Проект рассчитан на Pentium и 8 ГБ ОЗУ. Сам контейнер ограничен **512 МБ RAM и одним CPU**.

## Что уже работает

- agentless-сбор по SSH без установки агентов;
- TCP/SSH, load average, RAM, swap, диск, uptime, температура, OOM, systemd и Docker;
- проверки HTTP-кодов и задержки;
- контроль выбранных контейнеров и systemd units;
- динамическая норма `median + MAD`;
- корреляция симптомов в один инцидент;
- приоритет 0–100 с учётом важности узла и радиуса проблемы;
- SQLite-история инцидентов, действий и обучения;
- Beta-модель успешности действий;
- allowlist, уровни риска, cooldown и проверка восстановления;
- уведомления через собственный ntfy;
- тёмная веб-панель без тяжёлого фронтенда;
- REST API для интеграции с Zabbix, n8n и Semaphore;
- ноль Python-зависимостей: только стандартная библиотека.

## Быстрый запуск на Ubuntu Server

Требуются Git, Docker Engine и плагин Docker Compose.

```bash
git clone https://github.com/Grisha2401200258713655fffevrcefde/Codex.git LynxBrain
cd LynxBrain
sudo ./install.sh
```

Открой:

```text
http://IP_СЕРВЕРА:8088
```

Посмотреть журнал:

```bash
docker compose logs -f lynxbrain
```

Проверить состояние:

```bash
curl http://127.0.0.1:8088/health
curl http://127.0.0.1:8088/api/status | python3 -m json.tool
```

> Репозиторий временно опубликован в `Codex`, потому что подключённый GitHub-коннектор умеет записывать файлы в существующие репозитории, но не умеет создавать новый. Сам проект и все команды называются `LynxBrain`.

## Первичная настройка

После установки отредактируй:

```bash
nano config/hosts.json
```

Минимальный удалённый узел:

```json
{
  "name": "ubuntu-cloud",
  "address": "192.168.1.20",
  "mode": "ssh",
  "enabled": true,
  "importance": 9,
  "ssh_user": "admin",
  "ssh_port": 22,
  "ssh_key": "/home/lynx/.ssh/lynxbrain_ed25519",
  "strict_host_key_checking": true,
  "http_checks": [
    {"name": "Nextcloud", "url": "http://192.168.1.20:8080/status.php", "timeout": 5}
  ],
  "containers": ["nextcloud", "nextcloud-db", "nextcloud-redis"],
  "services": ["docker"],
  "allowed_actions": [
    "restart_container:nextcloud"
  ]
}
```

После изменения конфигурации перезапуск не обязателен: файл перечитывается перед каждым циклом. Для немедленной проверки:

```bash
TOKEN=$(grep '^LYNX_API_TOKEN=' .env | cut -d= -f2-)
curl -X POST http://127.0.0.1:8088/api/run-cycle \
  -H "Authorization: Bearer $TOKEN"
```

## Подготовка SSH

```bash
ssh-keygen -t ed25519 -f ~/.ssh/lynxbrain_ed25519 -C lynxbrain
ssh-copy-id -i ~/.ssh/lynxbrain_ed25519.pub admin@192.168.1.20
ssh-keyscan -H 192.168.1.20 >> ~/.ssh/known_hosts
```

Проверь вход без пароля:

```bash
ssh -i ~/.ssh/lynxbrain_ed25519 admin@192.168.1.20 'hostname; uptime'
```

Подробности и предупреждения по sudo: [docs/SSH_SETUP.md](docs/SSH_SETUP.md).

## Режимы исправления

По умолчанию:

```json
"auto_remediation": false
```

В этом режиме система только диагностирует и рекомендует. Это правильный режим на этапе обучения.

После проверки SSH, названий контейнеров и allowlist можно включить только безопасный уровень:

```json
"auto_remediation": true,
"max_automatic_action_level": 1
```

Уровни:

| Уровень | Пример | Автоматически |
|---:|---|---|
| 0 | Сбор и диагностика | Всегда |
| 1 | Restart одного контейнера, очистка старых journald-логов | Можно разрешить |
| 2 | Restart системного сервиса/Docker | Только осознанно |
| 3 | Reboot, сеть, удаление данных | Не реализовано намеренно |

LynxBrain **не умеет автоматически** перезагружать сервер, менять сеть, форматировать диски или удалять пользовательские данные.

## Ручное allowlisted-действие через API

```bash
TOKEN=$(grep '^LYNX_API_TOKEN=' .env | cut -d= -f2-)

curl -X POST http://127.0.0.1:8088/api/action \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "host": "ubuntu-cloud",
    "action": "restart_container:nextcloud"
  }'
```

Команда выполнится только тогда, когда строка полностью совпадает с `allowed_actions` выбранного узла.

## ntfy

В `config/hosts.json`:

```json
"ntfy": {
  "enabled": true,
  "base_url": "http://ntfy.lan",
  "topic": "lynxbrain"
}
```

При защищённом topic положи токен в `.env`:

```bash
NTFY_TOKEN=...
```

## Обратный прокси Nginx

```nginx
server {
    listen 80;
    server_name brain.lan;

    location / {
        proxy_pass http://IP_LYNXBRAIN:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

POST-методы всё равно требуют API-токен. Для доступа вне доверенной LAN добавь HTTPS и отдельную аутентификацию на reverse proxy.

## Архитектура

```text
┌─────────────────────────────────────────┐
│               LynxBrain                 │
│                                         │
│ Collector → Analyzer → Correlator       │
│                     ↓                   │
│ SQLite ← Learning ← Action Planner      │
│                     ↓                   │
│       Verifier ← Safe Executor          │
│                                         │
│ Dashboard / REST API / ntfy             │
└─────────────────────────────────────────┘
           │ SSH + HTTP
           ▼
 Ubuntu · Debian · Docker · systemd
```

Полное описание: [docs/ALGORITHM.md](docs/ALGORITHM.md).

## Разработка и проверки

Никаких pip-зависимостей для ядра нет.

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q lynxbrain tests
```

Локальный запуск без Docker:

```bash
cp config/hosts.example.json config/hosts.json
export LYNX_CONFIG="$PWD/config/hosts.json"
export LYNX_DB="$PWD/data/lynxbrain.db"
export LYNX_API_TOKEN="dev-token"
python3 -m lynxbrain
```

## Следующие этапы

- граф зависимостей сервисов между несколькими узлами;
- импорт триггеров Zabbix через webhook;
- Ansible/Semaphore executor вместо прямых команд;
- SMART/ZFS/MD RAID collectors;
- maintenance windows;
- подтверждение действий из Telegram/ntfy;
- экспорт Prometheus metrics;
- резервный контроллер и leader election.

## Безопасность

1. Не публикуй `.env`, приватные SSH-ключи и `config/hosts.json`.
2. Оставляй `StrictHostKeyChecking=true`.
3. Не выдавай SSH-пользователю `NOPASSWD: ALL`.
4. Помни: группа `docker` практически равна root-доступу.
5. Начинай с `auto_remediation=false`.
6. Разрешай только одно конкретное действие на один конкретный сервис.
7. Не выставляй порт 8088 напрямую в интернет.

Лицензия: MIT.
