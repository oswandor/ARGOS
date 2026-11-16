# Construye las imágenes del sandbox ARGOS.
#   .\docker\build.ps1                     # todas, tag 0.1.0
#   .\docker\build.ps1 -Tag dev -Only pdf,yara
param(
    [string]$Tag = "0.1.0",
    [string[]]$Only = @("pdf", "office", "js", "binary", "yara")
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not $Only -or $Only.Count -eq 0) { $Only = @("pdf", "office", "js", "binary", "yara") }

    Write-Host "== base ==" -ForegroundColor Cyan
    docker build -f docker/worker-base.Dockerfile -t "argos/worker-base:$Tag" .
    if ($LASTEXITCODE -ne 0) { throw "falló la imagen base" }

    foreach ($family in $Only) {
        Write-Host "== worker-$family ==" -ForegroundColor Cyan
        docker build `
            -f "docker/worker-$family.Dockerfile" `
            --build-arg "BASE_IMAGE=argos/worker-base:$Tag" `
            -t "argos/worker-$family`:$Tag" .
        if ($LASTEXITCODE -ne 0) { throw "falló worker-$family" }
    }

    Write-Host ""
    docker images --filter "reference=argos/worker*" --format "{{.Repository}}:{{.Tag}}  {{.Size}}"
}
finally {
    Pop-Location
}
