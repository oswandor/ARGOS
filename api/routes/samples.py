"""API REST de ARGOS.

Rutas canónicas descriptivas (qué se está subiendo/consultando) y alias antiguos
ocultos para no romper clientes existentes.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from api.security import require_api_key
from core.db import get_session
from core.ingest import IngestError, ingest
from core.models import Investigation, Sample
from core.report import to_html, to_markdown
from core.service import latest_investigation, run_investigation
from core.settings import get_settings
from core.storage import LocalStorage

router = APIRouter()


def _sample_payload(db: Session, sample: Sample) -> dict:
    investigation = latest_investigation(db, sample.id)
    children = db.scalars(select(Sample).where(Sample.parent_id == sample.id)).all()
    return {
        "sample_id": sample.id,
        "sha256": sample.sha256,
        "md5": sample.md5,
        "filename": sample.filename,
        "size": sample.size,
        "detected_type": sample.detected_type,
        "mime": sample.mime,
        "status": sample.status,
        "depth": sample.depth,
        "parent_id": sample.parent_id,
        "created_at": sample.created_at.isoformat() if sample.created_at else None,
        "children": [
            {
                "sample_id": c.id,
                "filename": c.filename,
                "detected_type": c.detected_type,
                "sha256": c.sha256,
                "size": c.size,
                "depth": c.depth,
            }
            for c in children
        ],
        "investigation": None
        if investigation is None
        else {
            "investigation_id": investigation.id,
            "status": investigation.status,
            "verdict": investigation.verdict,
            "confidence": investigation.confidence,
            "risk_score": investigation.risk_score,
            "llm_status": investigation.llm_status,
            "tokens_used": investigation.tokens_used,
            "error": investigation.error or None,
        },
    }


@router.post(
    "/malware-samples",
    status_code=202,
    tags=["malware samples"],
    summary="Subir una muestra de malware para analizar",
    description=(
        "Recibe un PDF, documento Office, JavaScript o binario autorizado, calcula su SHA-256, "
        "lo pone en cuarentena y lanza el análisis. Con `wait=true` espera el informe; con "
        "`wait=false` devuelve 202 y el análisis corre en segundo plano."
    ),
)
@router.post("/samples", status_code=202, include_in_schema=False, deprecated=True)
async def create_malware_sample(
    background: BackgroundTasks,
    file: UploadFile = File(..., description="Archivo sospechoso (máx. MAX_UPLOAD_MB)"),
    wait: bool = Query(
        default=False,
        description="true = esperar el análisis completo; false = devolver 202 y procesar en segundo plano",
    ),
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> JSONResponse:
    settings = get_settings()
    limit = settings.max_upload_mb * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"archivo mayor de {settings.max_upload_mb} MB")

    storage = LocalStorage(settings.blob_dir)
    try:
        sample, deduplicated = ingest(
            db, storage, settings, filename=file.filename or "muestra.bin", data=data
        )
    except IngestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db.commit()
    previous = latest_investigation(db, sample.id)

    if wait:
        # CrewAI y los workers Docker son síncronos; no deben bloquear ni
        # ejecutarse dentro del event loop de FastAPI.
        investigation_id = await run_in_threadpool(run_investigation, sample.id)
        db.expire_all()
        investigation = db.get(Investigation, investigation_id)
        return JSONResponse(
            status_code=202,
            content={
                "sample_id": sample.id,
                "sha256": sample.sha256,
                "detected_type": sample.detected_type,
                "deduplicated": deduplicated,
                "investigation_id": investigation_id,
                "status": investigation.status if investigation else "unknown",
                "verdict": investigation.verdict if investigation else None,
                "report_url": f"/malware-samples/{sample.id}/analysis-report",
            },
        )

    if previous is None or previous.status == "failed":
        background.add_task(run_investigation, sample.id)
        status = "queued"
    else:
        status = previous.status

    return JSONResponse(
        status_code=202,
        content={
            "sample_id": sample.id,
            "sha256": sample.sha256,
            "detected_type": sample.detected_type,
            "deduplicated": deduplicated,
            "status": status,
            "report_url": f"/malware-samples/{sample.id}/analysis-report",
        },
    )


@router.get(
    "/malware-samples",
    tags=["malware samples"],
    summary="Listar muestras de malware analizadas",
    description="Devuelve las últimas muestras con su estado de investigación y veredicto.",
)
@router.get("/samples", include_in_schema=False, deprecated=True)
def list_malware_samples(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> dict:
    samples = db.scalars(select(Sample).order_by(Sample.created_at.desc()).limit(limit)).all()
    return {"items": [_sample_payload(db, s) for s in samples], "count": len(samples)}


@router.get(
    "/malware-samples/{sample_id}",
    tags=["malware samples"],
    summary="Consultar una muestra de malware y su investigación",
    description="Metadatos, árbol de artefactos hijos y estado/veredicto de la investigación.",
)
@router.get("/samples/{sample_id}", include_in_schema=False, deprecated=True)
def get_malware_sample(
    sample_id: str,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> dict:
    sample = db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(status_code=404, detail="muestra no encontrada")
    return _sample_payload(db, sample)


def _load_report(db: Session, sample_id: str) -> dict:
    investigation = latest_investigation(db, sample_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="sin investigación para esta muestra")
    if not investigation.report_json:
        raise HTTPException(
            status_code=409,
            detail=f"informe no disponible (estado: {investigation.status})",
        )
    return json.loads(investigation.report_json)


@router.get(
    "/malware-samples/{sample_id}/analysis-report",
    tags=["analysis reports"],
    summary="Obtener el informe de análisis en JSON",
    description="Informe estable (esquema argos.report/1) con evidencia, IOCs, ATT&CK y cobertura.",
)
@router.get("/samples/{sample_id}/report", include_in_schema=False, deprecated=True)
def get_analysis_report(
    sample_id: str,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> JSONResponse:
    return JSONResponse(content=_load_report(db, sample_id))


@router.get(
    "/malware-samples/{sample_id}/analysis-report.md",
    tags=["analysis reports"],
    summary="Obtener el informe de análisis en Markdown",
    response_class=PlainTextResponse,
)
@router.get("/samples/{sample_id}/report.md", include_in_schema=False, deprecated=True)
def get_analysis_report_markdown(
    sample_id: str,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> PlainTextResponse:
    return PlainTextResponse(to_markdown(_load_report(db, sample_id)), media_type="text/markdown")


@router.get(
    "/malware-samples/{sample_id}/analysis-report.html",
    tags=["analysis reports"],
    summary="Obtener el informe de análisis en HTML",
    response_class=HTMLResponse,
)
@router.get("/samples/{sample_id}/report.html", include_in_schema=False, deprecated=True)
def get_analysis_report_html(
    sample_id: str,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> HTMLResponse:
    return HTMLResponse(to_html(_load_report(db, sample_id)))


@router.get(
    "/indicators-of-compromise",
    tags=["threat indicators"],
    summary="Buscar indicadores de compromiso",
    description="Busca por hash, dominio, URL, IP o correo en los IOCs correlacionados.",
)
@router.get("/iocs", include_in_schema=False, deprecated=True)
def search_indicators_of_compromise(
    value: str = Query(min_length=3, description="Hash, dominio, URL, IP o correo"),
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> dict:
    from core.models import IOC

    rows = db.scalars(select(IOC).where(IOC.value.contains(value)).limit(50)).all()
    return {
        "items": [
            {
                "id": row.id,
                "type": row.type,
                "value_defanged": row.defanged,
                "verdict": row.verdict,
                "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            }
            for row in rows
        ]
    }
