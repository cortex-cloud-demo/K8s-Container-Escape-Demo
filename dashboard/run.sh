#!/bin/bash
set -e

cd "$(dirname "$0")"

# Create venv if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "==> Creating Python virtual environment..."
    python3 -m venv .venv
fi

# Activate venv (Cross-platform compatibility)
if [ -f ".venv/Scripts/activate" ]; then
    # Windows (Git Bash / MinGW)
    source .venv/Scripts/activate
else
    # Linux / macOS
    source .venv/bin/activate
fi

# Install/update dependencies
echo "==> Installing dependencies..."
pip install -q -r requirements.txt

# Run the app
echo "==> Starting dashboard on http://localhost:5555"
python app.py
