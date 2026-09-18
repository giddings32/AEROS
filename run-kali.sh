#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
umask 077
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
if ! .venv/bin/python -c 'import docx, pypdf' >/dev/null 2>&1; then
  .venv/bin/python -m pip install -r requirements.txt
fi
printf 'Open http://127.0.0.1:%s/index.html in Firefox or Chromium.\n' "${AEROS_PORT:-8765}"
exec .venv/bin/python server.py
