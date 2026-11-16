"""Cliente del sandbox-runner interno usado por Docker Compose."""

from __future__ import annotations

import base64

import httpx

from core.settings import get_settings
from tools.base import ArtifactDraft, FindingDraft, ToolContext, ToolOutput


class RunnerUnavailable(RuntimeError):
    pass


def _headers() -> dict[str, str]:
    token = get_settings().runner_shared_token
    return {"X-ARGOS-Runner-Token": token} if token else {}


def runner_status() -> dict:
    settings = get_settings()
    if not settings.sandbox_runner_url or not settings.runner_shared_token:
        return {"available": False, "reason": "SANDBOX_RUNNER_URL o RUNNER_SHARED_TOKEN no configurado"}
    try:
        response = httpx.get(f"{settings.sandbox_runner_url.rstrip('/')}/health", headers=_headers(), timeout=3)
        response.raise_for_status()
        return {"available": True, **response.json()}
    except (httpx.HTTPError, ValueError) as exc:
        return {"available": False, "reason": str(exc)[:300]}


def run_in_runner(*, image: str, tool: str, ctx: ToolContext, timeout_s: float) -> ToolOutput:
    settings = get_settings()
    if not settings.sandbox_runner_url:
        raise RunnerUnavailable("SANDBOX_RUNNER_URL no configurado")
    payload = {
        "image": image,
        "tool": tool,
        "detected_type": ctx.detected_type,
        "timeout_s": timeout_s,
        "data_b64": base64.b64encode(ctx.data).decode("ascii"),
        "max_artifact_bytes": settings.max_artifact_bytes,
        "max_js_bytes": ctx.meta.get("max_js_bytes", settings.max_js_bytes),
        "max_streams": ctx.meta.get("max_streams", settings.max_streams),
    }
    try:
        response = httpx.post(
            f"{settings.sandbox_runner_url.rstrip('/')}/v1/run",
            headers=_headers(), json=payload, timeout=timeout_s + 30,
        )
        response.raise_for_status()
        result = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise RunnerUnavailable(f"sandbox-runner inaccesible: {exc}") from exc
    artifacts = [
        ArtifactDraft(kind=str(item.get("kind", "blob")), data=base64.b64decode(item["data_b64"]),
                      filename=str(item.get("filename", "")), note=str(item.get("note", "")))
        for item in result.get("artifacts", []) if isinstance(item, dict) and item.get("data_b64")
    ]
    return ToolOutput(
        status=str(result.get("status", "error")),
        findings=[FindingDraft.model_validate(item) for item in result.get("findings", []) if isinstance(item, dict)],
        artifacts=artifacts,
        data=result.get("data", {}) if isinstance(result.get("data"), dict) else {},
        warnings=[str(item) for item in result.get("warnings", [])][:20],
        metrics={str(k): float(v) for k, v in (result.get("metrics") or {}).items()},
        engines={str(k): str(v) for k, v in (result.get("engines") or {}).items()},
        tool_version=str(result.get("engine_version", "")),
    )
