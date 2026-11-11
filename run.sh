#!/usr/bin/env bash
set -e

if command -v python >/dev/null 2>&1; then
    PYTHON=python
elif command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
else
    echo "Python 3 was not found. Open this project in GitHub Codespaces or install Python 3."
    exit 1
fi

echo "[1/4] Installing project dependencies..."
"$PYTHON" -m pip install -r requirements.txt

echo "[2/4] Checking Python syntax..."
"$PYTHON" -m py_compile app.py test_app.py

echo "[3/4] Running project tests..."
"$PYTHON" -m unittest discover -v

echo "[4/4] Starting WebStrike..."
exec "$PYTHON" app.py
