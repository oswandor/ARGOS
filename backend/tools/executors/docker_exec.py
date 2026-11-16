"""Ejecución de herramientas dentro de contenedores Docker (sandbox).

El host solo hace tres cosas: escribe la muestra en un directorio temporal, lanza
un contenedor endurecido con esa carpeta montada en solo lectura y recoge el JSON
de resultado. El contenedor no tiene red, no es root, no puede escribir fuera de
``/out`` y muere al terminar.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import uuid
from functools import lru_cache
from pathlib import Path

from core.settings import get_settings
from tools.base import ArtifactDraft, FindingDraft, ToolContext, ToolOutput


class DockerUnavailable(RuntimeError):
    pass


class DockerRunError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def docker_available() -> bool:
    """True si hay daemon accesible (se cachea por proceso)."""
    binary = shutil.which(get_settings().docker_binary)
    if not binary:
        return False
    try:
        result = subprocess.run(
            [binary, "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return False


def image_available(image: str) -> bool:
    binary = shutil.which(get_settings().docker_binary)
    if not binary:
        return False
    try:
        result = subprocess.run(
            [binary, "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _mount_path(path: Path) -> str:
    """Ruta apta para ``docker run -v`` en Windows y Linux."""
    return str(path.resolve()).replace("\\", "/")


def build_run_command(
    *,
    image: str,
    tool: str,
    sample_path: Path,
    out_dir: Path,
    detected_type: str,
    settings,
    extra_env: dict[str, str] | None = None,
) -> list[str]:
    """Construye el argv de docker con el perfil de aislamiento del sandbox.

    Función pura para poder testear el endurecimiento sin daemon.
    """
    binary = settings.docker_binary
    name = f"argos-{uuid.uuid4().hex[:10]}"
    cmd = [
        binary,
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "128",
        "--memory",
        f"{settings.docker_memory_mb}m",
        "--memory-swap",
        f"{settings.docker_memory_mb}m",
        "--cpus",
        str(settings.docker_cpus),
        "--ulimit",
        "nofile=256:256",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--user",
        "10001:10001",
        "--workdir",
        "/work",
        "-v",
        f"{_mount_path(sample_path.parent)}:/work:ro",
        "-v",
        f"{_mount_path(out_dir)}:/out:rw",
    ]
    for key, value in (extra_env or {}).items():
        cmd += ["-e", f"{key}={value}"]
    cmd += [
        image,
        "python",
        "/opt/argos/entry.py",
        tool,
        f"/work/{sample_path.name}",
        "--type",
        detected_type,
        "--out",
        "/out",
    ]
    return cmd


def run_in_docker(
    *,
    image: str,
    tool: str,
    ctx: ToolContext,
    timeout_s: float,
) -> ToolOutput:
    settings = get_settings()
    if not docker_available():
        raise DockerUnavailable("daemon de Docker no disponible")
    if not image_available(image):
        raise DockerUnavailable(f"imagen no construida: {image}")

    work = Path(tempfile.mkdtemp(prefix="argos-work-"))
    out = Path(tempfile.mkdtemp(prefix="argos-out-"))
    sample_path = work / "sample.bin"
    sample_path.write_bytes(ctx.data)
    try:
        out.chmod(0o777)  # el contenedor corre con uid 10001
    except OSError:
        pass

    cmd = build_run_command(
        image=image,
        tool=tool,
        sample_path=sample_path,
        out_dir=out,
        detected_type=ctx.detected_type,
        settings=settings,
        extra_env={
            "ARGOS_MAX_JS_BYTES": str(ctx.meta.get("max_js_bytes", settings.max_js_bytes)),
            "ARGOS_MAX_STREAMS": str(ctx.meta.get("max_streams", settings.max_streams)),
            "ARGOS_MAX_ARTIFACT_BYTES": str(settings.max_artifact_bytes),
        },
    )

    try:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            container_name = cmd[cmd.index("--name") + 1]
            subprocess.run(
                [settings.docker_binary, "kill", container_name],
                capture_output=True,
                timeout=20,
                check=False,
            )
            return ToolOutput(
                status="timeout",
                warnings=[f"timeout del sandbox ({timeout_s:.0f}s)"],
                tool_id=tool,
            )

        result_path = out / "result.json"
        if not result_path.is_file():
            tail = (proc.stderr or proc.stdout or "").strip()[-800:]
            return ToolOutput(
                status="error",
                warnings=[f"el worker no produjo result.json (exit {proc.returncode}): {tail}"],
                tool_id=tool,
            )

        payload = json.loads(result_path.read_text(encoding="utf-8"))
        return _to_output(payload, out, tool)
    finally:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(out, ignore_errors=True)


def _to_output(payload: dict, out_dir: Path, tool: str) -> ToolOutput:
    findings = [
        FindingDraft(
            category=str(f.get("category", "other")),
            description=str(f.get("description", ""))[:2000],
            suspicious=bool(f.get("suspicious", False)),
            score=float(f.get("score", 0.0)),
            object_id=f.get("object_id"),
            raw_ref=f.get("raw_ref"),
        )
        for f in payload.get("findings", [])
        if isinstance(f, dict)
    ]

    artifacts: list[ArtifactDraft] = []
    for item in payload.get("artifacts", []):
        rel = str(item.get("path", ""))
        if not rel or "/" in rel or "\\" in rel or ".." in rel:
            continue
        path = out_dir / rel
        if not path.is_file():
            continue
        data = path.read_bytes()
        artifacts.append(
            ArtifactDraft(
                kind=str(item.get("kind", "blob")),
                data=data,
                filename=str(item.get("filename", rel)),
                note=str(item.get("note", "")),
            )
        )

    return ToolOutput(
        status=str(payload.get("status", "ok")),
        findings=findings,
        artifacts=artifacts,
        data=payload.get("data", {}),
        warnings=[str(w) for w in payload.get("warnings", [])][:20],
        metrics={k: float(v) for k, v in (payload.get("metrics") or {}).items()},
        engines={str(k): str(v) for k, v in (payload.get("engines") or {}).items()},
        tool_id=tool,
        tool_version=str(payload.get("engine_version", "")),
    )


def docker_status() -> dict:
    settings = get_settings()
    images = [
        f"{settings.worker_image_prefix}-pdf:{settings.worker_image_tag}",
        f"{settings.worker_image_prefix}-office:{settings.worker_image_tag}",
        f"{settings.worker_image_prefix}-js:{settings.worker_image_tag}",
        f"{settings.worker_image_prefix}-binary:{settings.worker_image_tag}",
        f"{settings.worker_image_prefix}-yara:{settings.worker_image_tag}",
    ]
    available = docker_available()
    return {
        "executor": settings.executor,
        "docker_available": available,
        "images": {image: (image_available(image) if available else False) for image in images},
        "isolation": {
            "network": "none",
            "read_only_rootfs": True,
            "cap_drop": "ALL",
            "no_new_privileges": True,
            "pids_limit": 128,
            "memory_mb": settings.docker_memory_mb,
            "cpus": settings.docker_cpus,
        },
        "note": "UNIX socket montado: no" if os.name != "nt" else "host Windows: sin socket dentro de workers",
    }
