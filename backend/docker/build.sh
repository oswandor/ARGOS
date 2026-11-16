#!/usr/bin/env bash
# Construye las imágenes del sandbox ARGOS (Linux/macOS).
set -euo pipefail

TAG="${TAG:-0.1.0}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

docker build -f docker/worker-base.Dockerfile -t "argos/worker-base:${TAG}" .

for family in pdf office js binary yara; do
  echo "== worker-${family} =="
  docker build \
    -f "docker/worker-${family}.Dockerfile" \
    --build-arg "BASE_IMAGE=argos/worker-base:${TAG}" \
    -t "argos/worker-${family}:${TAG}" .
done

docker images --filter "reference=argos/worker*" --format "{{.Repository}}:{{.Tag}}  {{.Size}}"
