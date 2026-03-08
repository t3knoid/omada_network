#!/usr/bin/env bash
# Start the Omada Network Documentation Generator web UI.
# Usage: ./start_web.sh [--host 0.0.0.0] [--port 5000]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "Installing dependencies..."
pip install -q -r requirements.txt

# Determine host and port from arguments (defaults match cli.py serve)
HOST="127.0.0.1"
PORT="5000"
while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        *) shift ;;
    esac
done

URL="http://${HOST}:${PORT}"
echo ""
echo "==> Omada Network Documentation Generator"
echo "==> Web UI will be available at: ${URL}"
echo ""

# Open the browser after a short delay so the server has time to start
( sleep 2 && \
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"; \
  elif command -v open >/dev/null 2>&1; then open "$URL"; \
  fi \
) &

exec python cli.py --log-file omada_network.log serve --host "$HOST" --port "$PORT"
