# Worker PDF: Didier Stevens (pdfid, pdf-parser), qpdf, poppler, pypdf.
ARG BASE_IMAGE=argos/worker-base:0.1.0
FROM ${BASE_IMAGE}

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends qpdf poppler-utils \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "pypdf>=5" "pikepdf>=9"

# Didier Stevens Suite (pdfid.py y pdf-parser.py). Fijar DSTEVENS_REF a un commit
# concreto para builds reproducibles.
ARG DSTEVENS_REF=master
RUN mkdir -p /opt/didier \
    && curl -fsSL "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/${DSTEVENS_REF}/pdfid.py" \
        -o /opt/didier/pdfid.py \
    && curl -fsSL "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/${DSTEVENS_REF}/pdf-parser.py" \
        -o /opt/didier/pdf-parser.py \
    && chmod 0555 /opt/didier/pdfid.py /opt/didier/pdf-parser.py

USER 10001:10001
