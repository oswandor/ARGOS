# Worker JavaScript: Node + box-js (emulación JScript/Windows Script Host).
ARG BASE_IMAGE=argos/worker-base:0.1.0
FROM ${BASE_IMAGE}

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# box-js es un proyecto antiguo: si npm no logra instalarlo, la imagen sigue
# siendo válida y el worker reporta "box-js no disponible" en vez de fingir.
RUN mkdir -p /opt/boxjs \
    && cd /opt/boxjs \
    && npm init -y >/dev/null 2>&1 \
    && (npm install --omit=dev --no-audit --no-fund box-js >/tmp/npm.log 2>&1 || true) \
    && chmod -R a+rX /opt/boxjs

RUN pip install --no-cache-dir "jsbeautifier>=1.15"

USER 10001:10001
