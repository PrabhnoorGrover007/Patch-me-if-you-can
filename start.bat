@echo off
REM One-command startup for Windows (cmd.exe). Verifies artefacts, builds the frontend if
REM needed, then serves API + dashboard from a single FastAPI process on port 8000.
setlocal
cd /d "%~dp0"

set PY=.venv\Scripts\python.exe
if not exist "%PY%" set PY=python

echo [start] using %PY%
"%PY%" --version

if not exist "artifacts\ranked_2026.parquet" (
  echo [start] model artefacts missing. Run the pipeline first:
  echo         %PY% run_all.py
  exit /b 1
)
if not exist "artifacts\model.joblib" (
  echo [start] model artefacts missing. Run the pipeline first:
  echo         %PY% run_all.py
  exit /b 1
)

if not exist "web\dist" (
  if not exist "web\node_modules" (
    echo [start] installing frontend dependencies...
    pushd web
    call npm install --no-audit --no-fund
    popd
  )
  echo [start] building frontend...
  pushd web
  call npm run build
  popd
)

echo [start] serving on http://127.0.0.1:8000  (API docs at /docs)
"%PY%" -m uvicorn api.main:app --host 127.0.0.1 --port 8000
endlocal
