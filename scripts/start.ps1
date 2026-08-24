$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$PythonTools = Join-Path $ProjectRoot ".venv\Scripts"
$bindAddress = if ($env:STILL_ALIVE_HOST) { $env:STILL_ALIVE_HOST } else { "127.0.0.1" }
$bindPort = if ($env:STILL_ALIVE_PORT) { $env:STILL_ALIVE_PORT } else { "8000" }

& (Join-Path $PythonTools "alembic.exe") upgrade head
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& (Join-Path $PythonTools "uvicorn.exe") "app.main:app" --host $bindAddress --port $bindPort
exit $LASTEXITCODE
