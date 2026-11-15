"""Ingesta: validación, hash, deduplicación y cuarentena."""

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.hashing import md5_bytes, sha256_bytes
from core.models import Sample, new_id
from core.settings import Settings
from core.storage import LocalStorage, sample_key
from tools.adapters.triage import detect


class IngestError(ValueError):
    pass


def sanitize_filename(name: str) -> str:
    cleaned = "".join(c for c in name if c.isprintable() and c not in '"\\/').strip()
    return cleaned[:180] or "muestra.bin"


def ingest(
    db: Session,
    storage: LocalStorage,
    settings: Settings,
    *,
    filename: str,
    data: bytes,
) -> tuple[Sample, bool]:
    """Devuelve (sample, deduplicado). Lanza IngestError si no es aceptable."""
    if not data:
        raise IngestError("archivo vacío")
    if len(data) > settings.max_upload_mb * 1024 * 1024:
        raise IngestError(f"archivo demasiado grande (máximo {settings.max_upload_mb} MB)")

    digest = sha256_bytes(data)
    existing = db.scalar(select(Sample).where(Sample.sha256 == digest))
    if existing:
        return existing, True

    safe_name = sanitize_filename(filename)
    ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
    detected, mime, _ = detect(data, safe_name)

    key = sample_key(digest)
    storage.put(key, data)

    sample = Sample(
        id=new_id("smp"),
        sha256=digest,
        md5=md5_bytes(data),
        size=len(data),
        filename=safe_name,
        extension=ext,
        detected_type=detected,
        mime=mime,
        storage_key=key,
        depth=0,
        status="received",
        meta=json.dumps({"source": "api"}),
    )
    db.add(sample)
    db.flush()
    return sample, False
