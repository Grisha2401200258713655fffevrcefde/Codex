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

RUN_USER="${SUDO_USER:-$(id -un)}"
RUN_UID="$(id -u "$RUN_USER")"
RUN_GID="$(id -g "$RUN_USER")"
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
SSH_DIR="$RUN_HOME/.ssh"
mkdir -p data config "$SSH_DIR"

if [[ ! -f config/hosts.json ]]; then
  cp config/hosts.example.json config/hosts.json
  echo "Создан config/hosts.json — отредактируй список серверов после запуска."
fi

HOST_PORT=8088
while ss -ltnH | awk '{print $4}' | grep -Eq "(^|:)$HOST_PORT$"; do
  HOST_PORT=$((HOST_PORT + 1))
done

if [[ ! -f .env ]]; then
  token="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(36))
PY
)"
  sed \
    -e "s|replace-with-a-long-random-token|${token}|" \
    -e "s|LOCAL_UID=1000|LOCAL_UID=${RUN_UID}|" \
    -e "s|LOCAL_GID=1000|LOCAL_GID=${RUN_GID}|" \
    -e "s|LYNX_HOST_PORT=8088|LYNX_HOST_PORT=${HOST_PORT}|" \
    -e "s|LYNX_SSH_DIR=/home/user/.ssh|LYNX_SSH_DIR=${SSH_DIR}|" \
    .env.example > .env
  echo "Создан .env с новым API-токеном и портом ${HOST_PORT}."
else
  grep -q '^LYNX_HOST_PORT=' .env || echo "LYNX_HOST_PORT=${HOST_PORT}" >> .env
  grep -q '^LYNX_SSH_DIR=' .env || echo "LYNX_SSH_DIR=${SSH_DIR}" >> .env
  sed -i "s/^LOCAL_UID=.*/LOCAL_UID=${RUN_UID}/" .env
  sed -i "s/^LOCAL_GID=.*/LOCAL_GID=${RUN_GID}/" .env
fi

chown -R "${RUN_UID}:${RUN_GID}" data config .env
chmod 600 .env

docker compose up -d --build

ACTUAL_PORT="$(grep '^LYNX_HOST_PORT=' .env | cut -d= -f2)"
echo
echo "LynxBrain запущен: http://$(hostname -I | awk '{print $1}'):${ACTUAL_PORT}"
echo "Логи: sudo docker compose logs -f lynxbrain"
echo "Настройка узлов: nano config/hosts.json"
