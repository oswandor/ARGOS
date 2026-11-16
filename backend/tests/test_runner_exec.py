from __future__ import annotations

import base64

from tools.base import ToolContext
from tools.executors import runner_exec


def test_runner_status_requires_configuration(monkeypatch) -> None:
    from core.settings import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "sandbox_runner_url", "")
    assert runner_exec.runner_status()["available"] is False


def test_runner_response_becomes_tool_output(monkeypatch) -> None:
    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "status": "ok",
                "findings": [{"category": "javascript", "description": "JS", "score": 2.0}],
                "artifacts": [{"kind": "vba", "filename": "M1", "data_b64": base64.b64encode(b"Sub X()").decode()}],
                "engines": {"engine": "1"},
            }

    from core.settings import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "sandbox_runner_url", "http://runner")
    monkeypatch.setattr(runner_exec.httpx, "post", lambda *args, **kwargs: Response())
    output = runner_exec.run_in_runner(
        image="argos/worker-pdf:0.1.0", tool="pdfid", ctx=ToolContext("s", "x.pdf", "pdf", b"pdf"), timeout_s=5
    )
    assert output.sandbox is False
    assert output.findings[0].category == "javascript"
    assert output.artifacts[0].data == b"Sub X()"
