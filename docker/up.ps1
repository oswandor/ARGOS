param(
    [switch]$ForceBuild,
    [string]$EnvFile = ".env.docker"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not (Test-Path $EnvFile)) {
        Copy-Item .env.docker.example $EnvFile
        Write-Host "Se creó $EnvFile." -ForegroundColor Yellow
        Write-Host "Añade DEEPSEEK_API_KEY y ejecuta de nuevo para activar los agentes." -ForegroundColor Yellow
    }

    # Token interno: se genera si sigue el placeholder de la plantilla.
    $content = Get-Content $EnvFile -Raw
    if ($content -match "cambiar-por-un-token-largo-y-aleatorio") {
        $token = [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
        $content = $content -replace "cambiar-por-un-token-largo-y-aleatorio", $token
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText((Join-Path (Get-Location) $EnvFile), $content, $utf8)
        Write-Host "RUNNER_SHARED_TOKEN generado automáticamente." -ForegroundColor Yellow
    }

    docker version --format '{{.Server.Version}}' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Docker no está disponible. Inicia Docker Desktop." }

    $tag = "0.1.0"
    $workers = @(
        "argos/worker-base:$tag",
        "argos/worker-pdf:$tag",
        "argos/worker-office:$tag",
        "argos/worker-js:$tag",
        "argos/worker-binary:$tag",
        "argos/worker-yara:$tag"
    )
    $missing = @()
    foreach ($image in $workers) {
        docker image inspect $image 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { $missing += $image }
    }

    if ($ForceBuild -or $missing.Count -gt 0) {
        Write-Host "Construyendo imagen base y workers (puede tardar varios minutos)..." -ForegroundColor Cyan
        docker compose --env-file $EnvFile build worker-base
        if ($LASTEXITCODE -ne 0) { throw "falló la imagen base" }
        docker compose --env-file $EnvFile build worker-pdf worker-office worker-js worker-binary worker-yara
        if ($LASTEXITCODE -ne 0) { throw "falló la construcción de un worker" }
    }
    else {
        Write-Host "Imágenes de workers presentes; se reutilizan (usa -ForceBuild para reconstruirlas)." -ForegroundColor DarkGray
    }

    $buildFlag = @()
    if ($ForceBuild) { $buildFlag = @("--build") }
    docker compose --env-file $EnvFile up @buildFlag --detach --wait postgres sandbox-runner api
    if ($LASTEXITCODE -ne 0) { throw "la pila no llegó a estado healthy" }

    Write-Host ""
    Write-Host "ARGOS listo:" -ForegroundColor Green
    Write-Host "  Swagger : http://127.0.0.1:8000/docs"
    Write-Host "  Salud   : http://127.0.0.1:8000/health"
    Write-Host "  Sandbox : http://127.0.0.1:8000/sandbox"
    Write-Host ""
    Write-Host "Logs: docker compose --env-file $EnvFile logs -f api"
    Write-Host "Stop: .\docker\down.ps1"
}
finally { Pop-Location }
