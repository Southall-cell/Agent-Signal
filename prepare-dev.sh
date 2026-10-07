#!/bin/sh
set -eu
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEV_DIR="$ROOT_DIR/.dev"
KEY_FILE="$DEV_DIR/demo-agent.pem"
REGISTRY_FILE="$DEV_DIR/agent_public_keys.json"
REGISTRATION_ENV="$DEV_DIR/registration.env"
mkdir -p "$DEV_DIR"
chmod 700 "$DEV_DIR"
if [ ! -e "$DEV_DIR/agents.sqlite3" ]; then
    (umask 077 && : > "$DEV_DIR/agents.sqlite3")
fi
chmod 600 "$DEV_DIR/agents.sqlite3"
PYTHON_BIN=${PYTHON_BIN:-python3}
if [ ! -f "$REGISTRATION_ENV" ]; then
    (umask 077 && "$PYTHON_BIN" -c 'import secrets; print("REGISTRATION_TOKEN=" + secrets.token_urlsafe(32))' > "$REGISTRATION_ENV")
fi
chmod 600 "$REGISTRATION_ENV"

if [ -f "$KEY_FILE" ] && [ -f "$REGISTRY_FILE" ]; then
    exit 0
fi
if [ -e "$KEY_FILE" ] || [ -e "$REGISTRY_FILE" ]; then
    echo "Incomplete development key setup. Remove $DEV_DIR and run this script again." >&2
    exit 1
fi

"$PYTHON_BIN" "$ROOT_DIR/generate_agent_keypair.py" \
    --agent-id demo-agent \
    --private-key-out "$KEY_FILE" \
    --registry "$REGISTRY_FILE"
