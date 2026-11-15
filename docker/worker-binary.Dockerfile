# Worker binario/shellcode: Capstone, LIEF, binutils (objdump/strings) y nasm.
ARG BASE_IMAGE=argos/worker-base:0.1.0
FROM ${BASE_IMAGE}

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends binutils nasm \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "capstone>=5" "lief>=0.15"

USER 10001:10001
