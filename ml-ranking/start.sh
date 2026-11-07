#!/usr/bin/env bash
# One-command startup: verifies artefacts, builds the frontend if needed, serves everything
# from a single FastAPI process on http://127.0.0.1:8000
set -euo pipefail
cd "$(dirname "$0")"

PY=".venv/Scripts/python.exe"
[ -x "$PY" ] || PY=".venv/bin/python"
[ -x "$PY" ] || PY="python"

echo "[start] python: $($PY --version 2>&1)"

if [ ! -f artifacts/ranked_2026.parquet ] || [ ! -f artifacts/model.joblib ]; then
  echo "[start] model artefacts missing. Run the pipeline first:"
  echo "        $PY run_all.py"
  exit 1
fi

if [ ! -d web/dist ]; then
  if [ -d web/node_modules ]; then
    echo "[start] building frontend..."
    (cd web && npm run build)
  else
    echo "[start] web/node_modules missing; installing and building..."
    (cd web && npm install --no-audit --no-fund && npm run build)
  fi
fi

echo "[start] serving API + dashboard on http://127.0.0.1:8000"
echo "[start] API docs: http://127.0.0.1:8000/docs   (Ctrl+C to stop)"
exec "$PY" -m uvicorn api.main:app --host 127.0.0.1 --port 8000
