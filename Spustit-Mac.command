#!/bin/bash
set -e
cd -- "$(dirname -- "$0")"

if ! command -v python3 >/dev/null 2>&1 ||
   ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
    printf '%s\n' 'Nainstaluj Python 3.11 nebo novější z https://www.python.org/downloads/macos/.'
    exit 1
fi

if [ ! -x .venv/bin/python ]; then
    python3 -m venv .venv
fi

if [ ! -f .venv/.rozbor-ready ] || [ requirements.txt -nt .venv/.rozbor-ready ]; then
    .venv/bin/python -m pip install -r requirements.txt
    .venv/bin/python -m playwright install chromium
    touch .venv/.rozbor-ready
fi

exec .venv/bin/python -X utf8 app.py
