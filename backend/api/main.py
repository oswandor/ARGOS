"""ARGOS — API FastAPI del MVP."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import meta, samples
from core.db import init_db
from core.settings import get_settings
from tools.bootstrap import register_all

logging.basicConfig(
    level=getattr(logging, get_settings().log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


class _DropHealthAccess(logging.Filter):
    """El healthcheck de Docker cada 5 s no debe inundar el log."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        return '"GET /health' not in message and '"GET /ready' not in message


class _DropApproxTokenWarning(logging.Filter):
    """CrewAI avisa en cada llamada de que no puede contar tokens exactos."""

    def filter(self, record: logging.LogRecord) -> bool:
        return "approximate input token count" not in record.getMessage()


logging.getLogger("uvicorn.access").addFilter(_DropHealthAccess())
logging.getLogger("crewai.llms.base_llm").addFilter(_DropApproxTokenWarning())
# httpx registra cada sondeo al runner y cada llamada a DeepSeek: ruido para el operador.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    register_all()
    yield


app = FastAPI(
    title="ARGOS",
    version="0.2.0",
    description=(
        "Laboratorio de análisis de malware documental: PDF, Office, JavaScript y shellcode. "
        "Sube una muestra de malware, ejecuta herramientas en un sandbox Docker y obtén un "
        "informe con evidencia trazable, IOCs y agentes CrewAI."
    ),
    openapi_tags=[
        {
            "name": "malware samples",
            "description": "Alta, listado y consulta de muestras de malware y sus investigaciones.",
        },
        {
            "name": "analysis reports",
            "description": "Informes de análisis en JSON, Markdown y HTML.",
        },
        {
            "name": "threat indicators",
            "description": "Indicadores de compromiso (IOC) correlacionados.",
        },
        {
            "name": "analysis tools",
            "description": "Catálogo de herramientas y su disponibilidad en el sandbox.",
        },
        {
            "name": "sandbox",
            "description": "Estado del aislamiento y de las imágenes de workers.",
        },
        {
            "name": "llm",
            "description": "Conectividad con DeepSeek.",
        },
        {
            "name": "platform status",
            "description": "Salud y estadísticas de la plataforma.",
        },
    ],
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in get_settings().cors_origins.split(",") if origin.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(samples.router)
app.include_router(meta.router)


@app.get("/", tags=["platform status"])
def root() -> dict:
    return {
        "name": "ARGOS",
        "version": "0.2.0",
        "docs": "/docs",
        "endpoints": [
            "POST /malware-samples",
            "GET /malware-samples",
            "GET /malware-samples/{sample_id}",
            "GET /malware-samples/{sample_id}/analysis-report",
            "GET /malware-samples/{sample_id}/analysis-report.md",
            "GET /malware-samples/{sample_id}/analysis-report.html",
            "GET /indicators-of-compromise?value=",
            "GET /analysis-tools",
            "GET /sandbox-status",
            "GET /analysis-statistics",
            "GET /health",
            "POST /llm/connection-test",
        ],
        "legacy_aliases": [
            "POST /samples",
            "GET /samples/{sample_id}/report",
            "GET /iocs",
            "GET /tools",
            "GET /sandbox",
            "GET /stats",
            "POST /llm/ping",
        ],
    }
