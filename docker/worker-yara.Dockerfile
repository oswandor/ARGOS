# Worker YARA: motor y libyara, sin herramientas de documento.
ARG BASE_IMAGE=argos/worker-base:0.1.0
FROM ${BASE_IMAGE}

USER root

RUN pip install --no-cache-dir "yara-python>=4.5"

USER 10001:10001
