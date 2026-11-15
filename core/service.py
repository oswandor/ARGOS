"""Servicio de ejecución de investigaciones (compartido por API y CLI)."""

from __future__ import annotations

from core.db import SessionLocal
from core.models import Investigation, Sample
from graphs.pipeline import Investigator


def run_investigation(sample_id: str) -> str:
    """Ejecuta el pipeline en su propia sesión. Devuelve investigation_id."""
    db = SessionLocal()
    try:
        sample = db.get(Sample, sample_id)
        if sample is None:
            raise LookupError(f"muestra no encontrada: {sample_id}")
        investigation = Investigator(db).run(sample)
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
