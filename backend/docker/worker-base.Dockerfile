# ARGOS worker base — Python 3.12 + código de análisis, usuario sin privilegios.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends file ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 argos \
    && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin argos

RUN pip install --no-cache-dir "pydantic>=2.9" "pydantic-settings>=2.5"

COPY core /opt/argos/core
COPY tools /opt/argos/tools
COPY workers /opt/argos/workers
COPY workers/entry.py /opt/argos/entry.py

WORKDIR /work
USER 10001:10001
