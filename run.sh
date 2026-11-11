#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")"

if command -v python >/dev/null 2>&1; then
    PYTHON=python
elif command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
else
    echo "ERROR: Python 3 was not found in this environment."
    exit 1
fi

export PORT="${PORT:-8000}"

echo "WebStrike setup"
echo "---------------"
echo "Python: $("$PYTHON" --version)"
echo "Preferred port: $PORT"
echo

echo "[1/4] Installing dependencies..."
"$PYTHON" -m pip install -r requirements.txt

echo
echo "[2/4] Checking Python files..."
"$PYTHON" -m py_compile app.py test_app.py

echo
echo "[3/4] Running tests..."
"$PYTHON" -m unittest discover -v

echo
echo "[4/4] Starting WebStrike..."
echo "When the server starts, leave this terminal open."
echo "Open the forwarded WebStrike port from the PORTS tab."
echo
exec "$PYTHON" app.py
