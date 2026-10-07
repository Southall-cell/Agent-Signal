#!/bin/sh
set -eu
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VENV_DIR="$ROOT_DIR/.venv"

if [ ! -x "$VENV_DIR/bin/python" ]; then
    python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/python" -m pip install -r "$ROOT_DIR/requirements.txt"

PYTHON_BIN="$VENV_DIR/bin/python" "$ROOT_DIR/prepare-dev.sh"
export AGENT_PUBLIC_KEYS_FILE="$ROOT_DIR/.dev/agent_public_keys.json"
export AGENTS_DB_FILE="$ROOT_DIR/.dev/agents.sqlite3"
REGISTRATION_TOKEN=$(sed -n 's/^REGISTRATION_TOKEN=//p' "$ROOT_DIR/.dev/registration.env")
export REGISTRATION_TOKEN
PORT=${PORT:-8000}
cd "$ROOT_DIR"
exec "$VENV_DIR/bin/python" -m uvicorn app:app --host 127.0.0.1 --port "$PORT"
