$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Entrypoint = Join-Path $ProjectRoot "start.py"

& $Python $Entrypoint
exit $LASTEXITCODE
