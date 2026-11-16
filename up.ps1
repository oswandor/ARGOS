param([switch]$ForceBuild)

$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    # El script existente prepara el archivo de entorno y construye las imágenes de workers.
    & ./backend/docker/up.ps1 -ForceBuild:$ForceBuild
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo iniciar el backend.' }
    docker compose up -d --build --wait
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo iniciar la pila completa.' }
    Write-Host 'Frontend: http://127.0.0.1:5173' -ForegroundColor Green
    Write-Host 'API:      http://127.0.0.1:8000/docs'
}
finally { Pop-Location }
