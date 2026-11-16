"""Servicio de ejecución de investigaciones (compartido por API y CLI)."""

from __future__ import annotations

from core.db import SessionLocal
from core.models import Investigation, InvestigationOptions, Sample
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
    finally:
        db.close()


def latest_investigation(db, sample_id: str) -> Investigation | None:
    from sqlalchemy import desc, select

    return db.scalar(
        select(Investigation)
        .where(Investigation.sample_id == sample_id)
        .order_by(desc(Investigation.started_at))
    )
