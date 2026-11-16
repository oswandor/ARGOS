"""Endpoints de plataforma: salud, sandbox, herramientas, LLM y estadísticas."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from api.security import require_api_key
from core import llm
from core.db import get_session
from core.models import Investigation, Sample
from core.settings import get_settings
from tools import registry

router = APIRouter()


@router.get(
    "/health",
    tags=["platform status"],
    summary="Salud de la plataforma",
    description="Estado de PostgreSQL, del sandbox y de la configuración del LLM.",
)
def health(db: Session = Depends(get_session)) -> dict:
    from tools.executors.docker_exec import docker_available
    from tools.executors.runner_exec import runner_status

    database = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        database = f"error: {exc}"
    settings = get_settings()
    runner = runner_status() if settings.executor == "runner" else None
    sandbox_available = (
        docker_available() if settings.executor != "runner" else bool(runner and runner["available"])
    )
    return {
        "status": "ok" if database == "ok" else "degraded",
        "version": "0.2.0-sandbox",
        "database": database,
        "executor": settings.executor,
        "docker_available": sandbox_available,
        "runner": runner,
        "llm_configured": settings.llm_enabled,
        "llm_model": settings.model_fast if settings.llm_enabled else None,
        "strict_privacy": settings.strict_privacy,
        "external_intel": settings.allow_external_intel,
    }


@router.get(
    "/sandbox-status",
    tags=["sandbox"],
    summary="Estado del sandbox de análisis",
    description="Daemon/runner, imágenes de workers disponibles y perfil de aislamiento.",
)
@router.get("/sandbox", include_in_schema=False, deprecated=True)
def sandbox_status(_: None = Depends(require_api_key)) -> dict:
    from tools.executors.docker_exec import docker_status
    from tools.executors.runner_exec import runner_status

    if get_settings().executor == "runner":
        status = runner_status()
        return {
            "executor": "runner",
            "docker_available": bool(status.get("available")),
            "images": status.get("images", {}),
            "isolation": status.get("isolation", "runner no disponible"),
            "note": "La API no tiene socket Docker; sandbox-runner valida y crea workers efímeros.",
            "reason": status.get("reason", ""),
        }
    return docker_status()


@router.get(
    "/analysis-tools",
    tags=["analysis tools"],
    summary="Catálogo de herramientas de análisis",
    description="Herramientas registradas, versión, formatos, disponibilidad e imagen de sandbox.",
)
@router.get("/tools", include_in_schema=False, deprecated=True)
def analysis_tools(_: None = Depends(require_api_key)) -> dict:
    return {"items": registry.list_tools()}


@router.post(
    "/llm/connection-test",
    tags=["llm"],
    summary="Probar la conexión con DeepSeek",
    description="Lista los modelos visibles para la clave configurada. No consume generación.",
)
@router.post("/llm/ping", include_in_schema=False, deprecated=True)
def llm_connection_test(_: None = Depends(require_api_key)) -> dict:
    return llm.ping(get_settings())


@router.get(
    "/analysis-statistics",
    tags=["platform status"],
    summary="Estadísticas de análisis",
    description="Número de muestras, investigaciones y distribución de veredictos.",
)
@router.get("/stats", include_in_schema=False, deprecated=True)
def analysis_statistics(
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> dict:
    samples = db.scalar(select(func.count()).select_from(Sample)) or 0
    investigations = db.scalar(select(func.count()).select_from(Investigation)) or 0
    rows = db.execute(
        select(Investigation.verdict, func.count()).group_by(Investigation.verdict)
    ).all()
    return {
        "samples": samples,
        "investigations": investigations,
        "by_verdict": {verdict: count for verdict, count in rows},
    }
