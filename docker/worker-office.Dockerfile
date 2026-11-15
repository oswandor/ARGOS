# Worker Office: oletools (olevba, oleobj, mraptor) sobre OOXML y OLE.
ARG BASE_IMAGE=argos/worker-base:0.1.0
FROM ${BASE_IMAGE}

USER root

RUN pip install --no-cache-dir "oletools>=0.60" "olefile>=0.47" "msoffcrypto-tool>=5"

USER 10001:10001
