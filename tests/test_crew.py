"""Tests de la capa multiagente CrewAI (sin llamadas reales a DeepSeek)."""

from __future__ import annotations

import json

import pytest

from agents.crew import CrewResult
from agents.schemas import AnalysisPlan, ReportNarrative, parse_model
from agents.tools import RunAnalysisTool
from graphs.pipeline import Investigator
from tests.fixtures.pdf_factory import malicious_pdf


def test_parse_model_tolerates_fences_and_trailing_comma() -> None:
    raw = '```json\n{"route": "pdf", "tools_used": ["yara"], "gaps": [], "rationale": "ok",}\n```'
    parsed = parse_model(raw, AnalysisPlan)
    assert parsed is not None
    assert parsed.route == "pdf"


def test_parse_model_rejects_garbage() -> None:
    assert parse_model("no hay json", AnalysisPlan) is None
    assert parse_model('{"route": 123}', AnalysisPlan) is None


def test_run_analysis_tool_caps_calls() -> None:
    calls: list[str] = []

    def runner(tool_id: str) -> dict:
        calls.append(tool_id)
        return {"status": "ok", "tool": tool_id}

    tool = RunAnalysisTool(runner=runner, max_calls=1)
    first = json.loads(tool._run(tool_id="yara", reason="baseline"))
    second = json.loads(tool._run(tool_id="pdfid", reason="extra"))
    assert first["status"] == "ok"
    assert second["status"] == "rejected"
    assert calls == ["yara"]


def _investigate(db, monkeypatch, crew_result: CrewResult):
    from core.ingest import ingest
    from core.settings import get_settings
    from core.storage import LocalStorage

    settings = get_settings()
    monkeypatch.setattr(settings, "deepseek_api_key", "test-key")
    monkeypatch.setattr(settings, "enable_llm", True)
    monkeypatch.setattr(settings, "crew_enabled", True)

    storage = LocalStorage(settings.blob_dir)
    sample, _ = ingest(db, storage, settings, filename="factura.pdf", data=malicious_pdf())
    db.commit()

    def fake_crew(inv, cfg, ensure_evidence=None):
        if ensure_evidence:
            ensure_evidence()
        return crew_result

    monkeypatch.setattr("graphs.pipeline.run_crew", fake_crew)
    investigator = Investigator(db)
    investigation = investigator.run(sample)
    assert investigation.status == "done", investigation.error
    return investigator, json.loads(investigation.report_json)


def test_crew_narrative_used_and_fallback_runs_tools(clean_db, monkeypatch) -> None:
    crew = CrewResult(
        ok=True,
        status="ok",
        plan={"route": "pdf", "tools_used": [], "gaps": [], "rationale": "plan de prueba"},
        narrative=ReportNarrative(
            summary="Resumen escrito por el crew.",
            attack_chain=["Paso observado"],
            recommendations=["Aislar el archivo"],
            confidence_adjustment=0.02,
        ).model_dump(),
        validation={"consistent": True, "contradictions": [], "unsupported_claims": []},
        tokens=123,
        duration_ms=456,
        agents=["Supervisor", "Redactor"],
    )
    investigator, report = _investigate(clean_db, monkeypatch, crew)

    # El crew no ejecutó herramientas: el pipeline aplica el plan determinista.
    assert "pdfid" in report["coverage"]["executed"]
    assert report["verdict"] in {"malicious", "suspicious"}
    # La narrativa del crew se usa y se registra.
    assert report["summary"] == "Resumen escrito por el crew."
    assert report["llm"]["mode"] == "crew"
    assert report["crew"]["tokens"] == 123
    assert report["crew"]["agents"] == ["Supervisor", "Redactor"]
    assert investigator.crew_meta["status"] == "ok"


def test_crew_failure_falls_back_to_single_redactor(clean_db, monkeypatch) -> None:
    crew = CrewResult(ok=False, status="error", errors=["boom"], duration_ms=10)
    monkeypatch.setattr(
        "graphs.pipeline.llm_review",
        lambda bundle, cfg: (None, {"status": "disabled", "model": "", "tokens": 0, "duration_ms": 0}),
    )
    _investigator, report = _investigate(clean_db, monkeypatch, crew)

    assert report["verdict"] in {"malicious", "suspicious"}
    assert report["llm"]["mode"] == "single_fallback"
    assert report["crew"]["status"] == "error"


def test_crew_tool_rejects_tool_outside_allowlist(clean_db, monkeypatch) -> None:
    from core.ingest import ingest
    from core.settings import get_settings
    from core.storage import LocalStorage

    settings = get_settings()
    monkeypatch.setattr(settings, "deepseek_api_key", "test-key")
    monkeypatch.setattr(settings, "enable_llm", True)
    storage = LocalStorage(settings.blob_dir)
    sample, _ = ingest(db=clean_db, storage=storage, settings=settings, filename="x.pdf", data=malicious_pdf())
    clean_db.commit()

    investigator = Investigator(clean_db)
    investigator.sample = sample
    result = investigator.execute_tool_for_crew("office_scan")
    assert result["status"] == "rejected"


@pytest.mark.parametrize("tool_id", ["triage", "intel"])
def test_crew_tool_rejects_backend_tools(clean_db, tool_id: str) -> None:
    from core.ingest import ingest
    from core.settings import get_settings
    from core.storage import LocalStorage

    settings = get_settings()
    storage = LocalStorage(settings.blob_dir)
    sample, _ = ingest(db=clean_db, storage=storage, settings=settings, filename="y.pdf", data=malicious_pdf())
    clean_db.commit()

    investigator = Investigator(clean_db)
    investigator.sample = sample
    assert investigator.execute_tool_for_crew(tool_id)["status"] == "rejected"
