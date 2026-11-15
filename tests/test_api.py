"""Tests de la API REST (TestClient, sin LLM)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from api.main import app
from tests.fixtures.pdf_factory import benign_pdf, malicious_pdf


def test_health_and_analysis_tools() -> None:
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["database"] == "ok"
        assert health.json()["llm_configured"] is False

        tools = client.get("/analysis-tools")
        assert tools.status_code == 200
        ids = {item["id"] for item in tools.json()["items"]}
        assert {"triage", "pdfid", "pdf_parser", "js_analyzer", "yara"} <= ids
        assert all(item["available"] for item in tools.json()["items"])

        sandbox = client.get("/sandbox-status")
        assert sandbox.status_code == 200
        assert "images" in sandbox.json()

        stats = client.get("/analysis-statistics")
        assert stats.status_code == 200
        assert "by_verdict" in stats.json()


def test_upload_and_analysis_report_flow() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/malware-samples",
            params={"wait": "true"},
            files={"file": ("factura_2026.pdf", malicious_pdf(), "application/pdf")},
        )
        assert response.status_code == 202, response.text
        payload = response.json()
        assert payload["detected_type"] == "pdf"
        assert payload["report_url"].startswith("/malware-samples/")
        sample_id = payload["sample_id"]

        detail = client.get(f"/malware-samples/{sample_id}")
        assert detail.status_code == 200
        assert detail.json()["investigation"]["status"] == "done"

        report = client.get(f"/malware-samples/{sample_id}/analysis-report")
        assert report.status_code == 200
        body = report.json()
        assert body["verdict"] in {"malicious", "suspicious"}
        assert body["sample"]["sha256"] == payload["sha256"]

        markdown = client.get(f"/malware-samples/{sample_id}/analysis-report.md")
        assert markdown.status_code == 200
        assert "Informe ARGOS" in markdown.text

        html = client.get(f"/malware-samples/{sample_id}/analysis-report.html")
        assert html.status_code == 200
        assert "<html" in html.text


def test_upload_benign_pdf() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/malware-samples",
            params={"wait": "true"},
            files={"file": ("factura.pdf", benign_pdf(), "application/pdf")},
        )
        assert response.status_code == 202
        sample_id = response.json()["sample_id"]
        report = client.get(f"/malware-samples/{sample_id}/analysis-report").json()
        assert report["verdict"] in {"benign", "suspicious"}
        assert report["risk_score"] <= 2.0


def test_report_not_found() -> None:
    with TestClient(app) as client:
        assert client.get("/malware-samples/smp_inexistente/analysis-report").status_code == 404


def test_legacy_endpoint_aliases_still_work() -> None:
    """Los nombres antiguos siguen disponibles para no romper clientes."""
    with TestClient(app) as client:
        response = client.post(
            "/samples",
            params={"wait": "true"},
            files={"file": ("legacy.pdf", benign_pdf(), "application/pdf")},
        )
        assert response.status_code == 202
        sample_id = response.json()["sample_id"]
        assert client.get(f"/samples/{sample_id}/report").status_code == 200
        assert client.get(f"/samples/{sample_id}/report.md").status_code == 200
        assert client.get(f"/samples/{sample_id}/report.html").status_code == 200
        assert client.get("/tools").status_code == 200
        assert client.get("/sandbox").status_code == 200
        assert client.get("/stats").status_code == 200
        assert client.get("/iocs?value=malicious.example").status_code == 200
