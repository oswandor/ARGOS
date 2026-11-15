"""Tests de herramientas (adaptadores) — sin ejecución de muestras."""

from __future__ import annotations

import pytest

from core.policy import Budget
from tests.fixtures.pdf_factory import (
    benign_pdf,
    docm_bytes,
    malicious_pdf,
    packed_js,
    shellcode_blob,
)
from tools import registry
from tools.base import ToolContext
from tools.bootstrap import register_all

register_all()


def run_tool(tool_id: str, data: bytes, *, filename: str, detected: str, meta: dict | None = None):
    ctx = ToolContext(
        sample_id="smp_test",
        filename=filename,
        detected_type=detected,
        data=data,
        meta=meta or {},
    )
    return registry.run(tool_id, ctx, Budget())


def test_triage_detects_pdf_and_mismatch() -> None:
    out = run_tool("triage", benign_pdf(), filename="factura.pdf", detected="pdf")
    assert out.status == "ok"
    assert out.data["detected_type"] == "pdf"
    assert out.data["mime"] == "application/pdf"

    mismatch = run_tool("triage", benign_pdf(), filename="factura.exe", detected="pdf")
    categories = {f.category for f in mismatch.findings}
    assert "extension_mismatch" in categories


def test_pdfid_counts_dangerous_tokens() -> None:
    out = run_tool("pdfid", malicious_pdf(), filename="x.pdf", detected="pdf")
    assert out.status == "ok"
    tokens = out.data["tokens"]
    assert tokens["/JavaScript"] >= 1
    assert tokens["/OpenAction"] >= 1
    assert out.data["has_openaction"] is True
    assert any(f.category == "javascript" for f in out.findings)


def test_pdf_parser_extracts_javascript_and_embedded() -> None:
    out = run_tool(
        "pdf_parser",
        malicious_pdf(with_embedded=True),
        filename="x.pdf",
        detected="pdf",
        meta={"max_js_bytes": 200_000, "max_streams": 400},
    )
    assert out.status == "ok"
    assert out.data["objects_total"] >= 6
    kinds = {a.kind for a in out.artifacts}
    assert "javascript" in kinds
    assert "embedded" in kinds
    js = [a for a in out.artifacts if a.kind == "javascript"][0]
    assert b"malicious.example" in js.data
    assert any(f.category == "pdf_action" for f in out.findings)


def test_js_analyzer_extracts_iocs_and_apis() -> None:
    out = run_tool(
        "js_analyzer",
        packed_js(),
        filename="dropper.js",
        detected="javascript",
        meta={"max_js_bytes": 200_000},
    )
    assert out.status == "ok"
    values = {i["value"] for i in out.data["iocs"]}
    assert "http://evil.example/x" in values
    assert "fromCharCode" in out.data["deobfuscation_steps"]
    assert "percent_unescape" in out.data["deobfuscation_steps"]
    assert out.data["suspicious_tokens"].get("String.fromCharCode", 0) >= 1


def test_office_docm_extracts_vba() -> None:
    out = run_tool("office_scan", docm_bytes(), filename="macro.docm", detected="office")
    assert out.status == "ok"
    assert out.data["container"] == "ooxml"
    assert any(a.kind == "vba" for a in out.artifacts)
    categories = {f.category for f in out.findings}
    assert "macro" in categories
    assert "autoexec" in categories
    assert "AutoOpen" in out.data["autoexec"]


def test_shellcode_architecture_and_disassembly() -> None:
    out = run_tool("shellcode", shellcode_blob(), filename="payload.bin", detected="shellcode")
    assert out.status == "ok"
    assert out.data["architecture"] == "x86"
    assert len(out.data["instructions"]) > 0


def test_yara_matches_pdf_javascript_rule() -> None:
    out = run_tool("yara", malicious_pdf(), filename="x.pdf", detected="pdf")
    assert out.status == "ok"
    rules = {m["rule"] for m in out.data["matches"]}
    assert "ARGOS_PDF_JS_AUTOACTION" in rules


def test_policy_blocks_tool_not_allowed_for_type() -> None:
    from core.policy import PolicyError

    with pytest.raises(PolicyError):
        run_tool("pdf_parser", docm_bytes(), filename="x.docm", detected="office")


def test_tool_unavailable_is_reported_not_raised(monkeypatch) -> None:
    from core import policy

    def _fail(ctx):  # pragma: no cover - no debería ejecutarse
        raise AssertionError("no debe ejecutarse una herramienta no disponible")

    spec = registry.ToolSpec(
        id="fake_tool",
        name="Fake",
        version="0",
        formats=("pdf",),
        description="prueba",
        requires=("modulo_que_no_existe_123",),
    )
    registry.register(spec, _fail)
    allowed = (*policy.ALLOWLIST["pdf"], "fake_tool")
    monkeypatch.setitem(policy.ALLOWLIST, "pdf", allowed)
    try:
        out = registry.run(
            "fake_tool",
            ToolContext("smp", "x.pdf", "pdf", b"%PDF-1.7"),
            Budget(),
        )
    finally:
        registry.unregister("fake_tool")
    assert out.status == "unavailable"
    assert "no disponible" in out.warnings[0]
