"""Servicio de ejecución de investigaciones (compartido por API y CLI)."""

from __future__ import annotations

from core.db import SessionLocal
from core.models import Investigation, InvestigationEvent, InvestigationOptions, Sample, utcnow
from core.settings import get_settings
from graphs.pipeline import Investigator


def run_investigation(sample_id: str, investigation_id: str | None = None) -> str:
    """Ejecuta el pipeline en su propia sesión. Devuelve investigation_id."""
    db = SessionLocal()
    try:
        sample = db.get(Sample, sample_id)
        if sample is None:
            raise LookupError(f"muestra no encontrada: {sample_id}")
        investigation = db.get(Investigation, investigation_id) if investigation_id else None
        options = db.get(InvestigationOptions, investigation_id) if investigation_id else None
        settings = get_settings()
        if options:
            settings = settings.model_copy(update={"enable_llm": options.enable_llm,
                "crew_enabled": options.crew_enabled, "strict_privacy": options.strict_privacy})
        investigation = Investigator(db, settings).run(sample, investigation)
        return investigation.id
    except Exception as exc:
        db.rollback()
        if investigation_id:
            investigation = db.get(Investigation, investigation_id)
            if investigation is not None and investigation.status not in {"done", "failed"}:
                investigation.status = "failed"
                investigation.error = f"{type(exc).__name__}: {exc}"[:2000]
                investigation.finished_at = utcnow()
                sample = db.get(Sample, sample_id)
                if sample is not None:
                    sample.status = "failed"
                db.add(InvestigationEvent(investigation_id=investigation_id, phase="investigation",
                                          level="error", message="La investigación terminó con error"))
                db.commit()
        raise
    finally:
        db.close()


def latest_investigation(db, sample_id: str) -> Investigation | None:
    from sqlalchemy import desc, select

    return db.scalar(
        select(Investigation)
        .where(Investigation.sample_id == sample_id)
        .order_by(desc(Investigation.started_at))
    )
