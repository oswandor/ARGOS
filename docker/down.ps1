param([switch]$DeleteData, [string]$EnvFile = ".env.docker")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if ($DeleteData) { docker compose --env-file $EnvFile down --volumes }
    else { docker compose --env-file $EnvFile down }
} finally { Pop-Location }
