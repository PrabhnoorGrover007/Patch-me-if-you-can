@echo off
REM One-command startup for Windows (cmd.exe): FastAPI on :8000, Next.js on :3000.
setlocal
cd /d "%~dp0"

REM Optional local configuration, including watsonx.ai credentials.
if exist .env (
  for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env") do (
    if not "%%~A"=="" set "%%~A=%%~B"
  )
)

set PY=.venv\Scripts\python.exe
if not exist "%PY%" set PY=python

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

if not exist "app\node_modules" (
  echo [start] installing frontend dependencies...
  pushd app
  call npm install --no-audit --no-fund
  popd
)
if not exist "app\.next" (
  echo [start] building frontend...
  pushd app
  call npm run build
  popd
)

set "LOCAL_GRANITE_URL=http://127.0.0.1:8081"
if exist "local_ai\runtime\llama-server.exe" if exist "local_ai\models\granite-3.3-2b-instruct-Q3_K_M.gguf" (
  curl -fsS http://127.0.0.1:8081/health >nul 2>&1
  if errorlevel 1 (
    echo [start] local Granite AI: %LOCAL_GRANITE_URL%
    start "Granite AI" /b "local_ai\runtime\llama-server.exe" -m "local_ai\models\granite-3.3-2b-instruct-Q3_K_M.gguf" -c 2048 -t 4 -b 256 --host 127.0.0.1 --port 8081
    timeout /t 8 /nobreak >nul
  )
)

echo [start] API:  http://127.0.0.1:8000
echo [start] UI:   http://127.0.0.1:3000
echo [start] docs: http://127.0.0.1:8000/docs  (Ctrl+C to stop)

start /b "" "%PY%" -m uvicorn api.main:app --host 127.0.0.1 --port 8000
timeout /t 2 /nobreak >nul

pushd app
set API_BASE=http://127.0.0.1:8000
call npm start
popd
endlocal
