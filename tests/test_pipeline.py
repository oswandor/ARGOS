"""Tests de integración del pipeline (sin LLM)."""

from __future__ import annotations

import json

from core.ingest import ingest
from core.settings import get_settings
from core.storage import LocalStorage
from graphs.pipeline import Investigator
from tests.fixtures.pdf_factory import benign_pdf, docm_bytes, malicious_pdf, shellcode_blob


def _investigate(db, filename: str, data: bytes):
    settings = get_settings()
    storage = LocalStorage(settings.blob_dir)
    sample, _ = ingest(db, storage, settings, filename=filename, data=data)
    db.commit()
    investigation = Investigator(db).run(sample)
    assert investigation.status == "done", investigation.error
    return sample, json.loads(investigation.report_json)


def test_pdf_investigation_end_to_end(clean_db) -> None:
    sample, report = _investigate(clean_db, "factura_2026.pdf", malicious_pdf(with_embedded=True))

    assert report["schema"] == "argos.report/1"
    assert report["verdict"] in {"malicious", "suspicious"}
    assert report["risk_score"] > 2.0
    assert report["sample"]["sha256"] == sample.sha256
    assert "pdfid" in report["coverage"]["executed"]
    assert "pdf_parser" in report["coverage"]["executed"]

    # Toda afirmación técnica tiene evidencia
    assert report["findings"]
    evidence_ids = {item["evidence_id"] for item in report["findings"]}
    assert all(eid.startswith("ev_") for eid in evidence_ids)

    # IOCs defanged, nunca en claro
    assert report["iocs"]
    assert all("http://" not in ioc["value"] for ioc in report["iocs"])
    assert any(ioc["known"] for ioc in report["iocs"])

    # Artefacto hijo: DOCM embebido en el PDF
    assert report["children"]
    assert any(child["type"] == "office" for child in report["children"])

    # El informe declara sus límites y que el LLM está deshabilitado
    assert report["limitations"]
    assert report["llm"]["status"] == "disabled"
    assert "comportamiento real" in " ".join(report["limitations"]).lower()


def test_benign_pdf_not_flagged(clean_db) -> None:
    _, report = _investigate(clean_db, "factura.pdf", benign_pdf())
    assert report["verdict"] in {"benign", "suspicious"}
    assert report["risk_score"] <= 2.0


def test_docm_macro_detection(clean_db) -> None:
    _, report = _investigate(clean_db, "macro.docm", docm_bytes())
    categories = {f["category"] for f in report["findings"]}
    assert "macro" in categories
    assert "autoexec" in categories
    assert report["verdict"] in {"malicious", "suspicious"}


def test_shellcode_blob(clean_db) -> None:
    _, report = _investigate(clean_db, "payload.bin", shellcode_blob())
    assert report["sample"]["detected_type"] == "shellcode"
    assert any(f["category"] == "architecture" for f in report["findings"])


def test_deduplication_returns_same_sample(clean_db) -> None:
    settings = get_settings()
    storage = LocalStorage(settings.blob_dir)
    first, dup1 = ingest(clean_db, storage, settings, filename="a.pdf", data=benign_pdf())
    second, dup2 = ingest(clean_db, storage, settings, filename="b.pdf", data=benign_pdf())
    assert dup1 is False
    assert dup2 is True
    assert first.id == second.id
