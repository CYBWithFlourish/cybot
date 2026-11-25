#!/bin/sh
# Sprite bootstrap. Run this inside the Sprite shell, or tell the
# coding agent that already lives on the Sprite to run it.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DATA="${CYBOT_DATA_DIR:-$HOME/cybot-data}"
mkdir -p "$DATA"
chmod 700 "$DATA"

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

if [ "${CYBOT_WITH_OLLAMA:-}" = "1" ]; then
  sh "$ROOT/scripts/install-ollama-local.sh"
fi

PY="$ROOT/.venv/bin/python"
if command -v sprite-env >/dev/null 2>&1; then
  if sprite-env services list 2>/dev/null | grep -q cybot; then
    sprite-env services restart cybot || true
  else
    sprite-env services create cybot \
      --cmd "$PY" \
      --args "-m,cybot,serve,--host,0.0.0.0,--port,8641" \
      --dir "$ROOT" \
      --http-port 8641 \
      --env "CYBOT_DATA_DIR=$DATA,CYBOT_DEMO=1" \
      || sprite-env services restart cybot
  fi
  echo "CYBOT is a Sprite service on port 8641."
  echo "Open the Sprite in the Fly.io dashboard and set URL auth to Public."
  echo "The dashboard still asks you to create a password on first visit."
else
  echo "Not inside a Sprite. Start it with:"
  echo "  CYBOT_DATA_DIR=$DATA CYBOT_DEMO=1 $PY -m cybot serve --host 0.0.0.0 --port 8641"
fi
