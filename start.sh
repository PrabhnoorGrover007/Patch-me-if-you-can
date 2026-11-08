#!/usr/bin/env bash
# One command: FastAPI on :8000 plus the Next.js dashboard on :3000.
set -euo pipefail
cd "$(dirname "$0")"

# Optional local configuration, including watsonx.ai credentials.
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

PY=".venv/Scripts/python.exe"
[ -x "$PY" ] || PY=".venv/bin/python"
[ -x "$PY" ] || PY="python"

if [ ! -f artifacts/ranked_2026.parquet ] || [ ! -f artifacts/model.joblib ]; then
  echo "[start] model artefacts missing. Run the pipeline first:"
  echo "        $PY run_all.py"
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "[start] npm is required for the Next.js frontend."
  exit 1
fi

if [ ! -d app/node_modules ]; then
  echo "[start] installing frontend dependencies..."
  (cd app && npm install --no-audit --no-fund)
fi

if [ ! -d app/.next ]; then
  echo "[start] building frontend..."
  (cd app && npm run build)
fi

LOCAL_AI_PID=""
LOCAL_AI_PORT="${LOCAL_GRANITE_PORT:-8081}"
LOCAL_AI_URL="${LOCAL_GRANITE_URL:-http://127.0.0.1:$LOCAL_AI_PORT}"
LOCAL_AI_SERVER="$PWD/local_ai/runtime/llama-server.exe"
LOCAL_AI_MODEL="$PWD/local_ai/models/granite-3.3-2b-instruct-Q3_K_M.gguf"
if [ -x "$LOCAL_AI_SERVER" ] && [ -f "$LOCAL_AI_MODEL" ]; then
  if curl -fsS "$LOCAL_AI_URL/health" >/dev/null 2>&1; then
    echo "[start] local Granite AI: already running at $LOCAL_AI_URL"
  else
    echo "[start] local Granite AI: $LOCAL_AI_URL"
    "$LOCAL_AI_SERVER" -m "$LOCAL_AI_MODEL" -c 2048 -t 4 -b 256 \
      --host 127.0.0.1 --port "$LOCAL_AI_PORT" \
      > app/.next/llama.log 2>&1 &
    LOCAL_AI_PID=$!
    for _ in $(seq 1 60); do
      if curl -fsS "$LOCAL_AI_URL/health" >/dev/null 2>&1; then break; fi
      sleep 0.5
    done
    if ! curl -fsS "$LOCAL_AI_URL/health" >/dev/null 2>&1; then
      echo "[start] local AI unavailable; grounded answers remain active. See app/.next/llama.log"
      LOCAL_AI_PID=""
    fi
  fi
  export LOCAL_GRANITE_URL="$LOCAL_AI_URL"
fi

echo "[start] python: $($PY --version 2>&1)"
echo "[start] API:  http://127.0.0.1:8000"
echo "[start] UI:   http://127.0.0.1:3000"
echo "[start] docs: http://127.0.0.1:8000/docs   (Ctrl+C to stop)"

"$PY" -m uvicorn api.main:app --host 127.0.0.1 --port 8000 &
API_PID=$!
cleanup() {
  kill "$API_PID" >/dev/null 2>&1 || true
  if [ -n "$LOCAL_AI_PID" ]; then
    if command -v taskkill >/dev/null 2>&1; then
      taskkill //F //T //PID "$LOCAL_AI_PID" >/dev/null 2>&1 || true
    else
      kill "$LOCAL_AI_PID" >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT INT TERM

for _ in $(seq 1 40); do
  if curl -fsS http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

if ! kill -0 "$API_PID" >/dev/null 2>&1; then
  echo "[start] API failed to start. Check the traceback above."
  exit 1
fi

(cd app && API_BASE=http://127.0.0.1:8000 npm start)
