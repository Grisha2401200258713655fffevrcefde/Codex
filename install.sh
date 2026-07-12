#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker не найден. Установи Docker Engine и повтори запуск." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Не найден плагин docker compose." >&2
  exit 1
fi

mkdir -p data config
if [[ ! -f config/hosts.json ]]; then
  cp config/hosts.example.json config/hosts.json
  echo "Создан config/hosts.json — отредактируй список серверов после запуска."
fi

if [[ ! -f .env ]]; then
  token="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(36))
PY
)"
  sed -e "s|replace-with-a-long-random-token|${token}|" -e "s|LOCAL_UID=1000|LOCAL_UID=$(id -u)|" -e "s|LOCAL_GID=1000|LOCAL_GID=$(id -g)|" .env.example > .env
  chmod 600 .env
  echo "Создан .env с новым API-токеном."
fi

sudo chown -R "$(id -u):$(id -g)" data config .env
docker compose up -d --build

echo
echo "LynxBrain запущен: http://$(hostname -I | awk '{print $1}'):8088"
echo "Логи: docker compose logs -f lynxbrain"
echo "Настройка узлов: nano config/hosts.json"
