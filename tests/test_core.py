"""Tests de núcleo: sanitización, política y scoring."""
from __future__ import annotations

import pytest

from core.policy import Budget, BudgetExceeded, PolicyError, authorize
from core.sanitizer import defang, defang_url, redact_text, sanitize_bundle
from core.scoring import aggregate


def test_defang_url_and_domain() -> None:
    assert defang_url("http://malicious.example/a.exe") == "hxxp://malicious[.]example/a[.]exe"
    assert defang("1.2.3.4", "ip") == "1[.]2[.]3[.]4"
    assert defang("evil.example", "domain") == "evil[.]example"


def test_redact_removes_paths_and_secrets() -> None:
    text = r"error en C:\Users\oswan\Desktop\malware.exe con api_key=sk-abcdefghijklmnop"
    cleaned = redact_text(text)
    assert "oswan" not in cleaned
    assert "sk-abcdefghijklmnop" not in cleaned


def test_sanitize_bundle_never_leaks_bytes_or_urls() -> None:
    bundle = {
        "raw": b"MZ\x90\x00payload",
        "url": "http://evil.example/x",
        "nested": [{"path": r"C:\Users\oswan\a.txt"}],
    }
    safe = sanitize_bundle(bundle)
    assert safe["raw"] == "[bytes omitidos]"
    assert "http://" not in str(safe)
    assert "oswan" not in str(safe)


def test_policy_allowlist() -> None:
    authorize("pdfid", "pdf")
    with pytest.raises(PolicyError):
        authorize("office_scan", "pdf")
    with pytest.raises(PolicyError):
        authorize("js_analyzer", "office", is_child=True)


def test_budget_limits() -> None:
    budget = Budget(max_tool_calls=1)
    budget.spend_tool_call("triage")
    with pytest.raises(BudgetExceeded):
        budget.spend_tool_call("pdfid")


def test_aggregate_escalates_with_correlation() -> None:
    findings = [
        {"category": "javascript", "suspicious": True, "score": 2.5},
        {"category": "pdf_action", "suspicious": True, "score": 2.0},
        {"category": "downloader", "suspicious": True, "score": 3.0},
    ]
    coverage = {"executed": ["pdfid", "pdf_parser"], "unavailable": [], "skipped": []}
    result = aggregate(findings, coverage, "pdf", [])
    assert result.risk_score >= 7.0
    assert result.verdict == "malicious"
    assert result.mitre
    assert result.limitations


def test_aggregate_inconclusive_without_content_tools() -> None:
    result = aggregate([], {"executed": ["triage"], "unavailable": [], "skipped": []}, "unknown", [])
    assert result.verdict == "inconclusive"
