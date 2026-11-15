"""Sandbox runner: la única parte de Compose que puede hablar con Docker."""

from __future__ import annotations

import base64
import io
import json
import os
import secrets
import tarfile
import uuid
from collections.abc import Iterator

from docker.errors import DockerException, NotFound
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

import docker

PREFIX = os.getenv("WORKER_IMAGE_PREFIX", "argos/worker")
TAG = os.getenv("WORKER_IMAGE_TAG", "0.1.0")
BASE_IMAGE = f"{PREFIX}-base:{TAG}"
TOKEN = os.getenv("RUNNER_SHARED_TOKEN", "")
MAX_REQUEST_BYTES = int(os.getenv("RUNNER_MAX_REQUEST_BYTES", str(50 * 1024 * 1024)))
MAX_RESULT_BYTES = int(os.getenv("RUNNER_MAX_RESULT_BYTES", str(1024 * 1024)))
ALLOWED = {
    f"{PREFIX}-pdf:{TAG}": {"pdfid", "pdf_parser"},
    f"{PREFIX}-office:{TAG}": {"office"},
    f"{PREFIX}-js:{TAG}": {"js"},
    f"{PREFIX}-binary:{TAG}": {"binary"},
    f"{PREFIX}-yara:{TAG}": {"yara"},
}


class RunRequest(BaseModel):
    image: str
    tool: str
    detected_type: str = "unknown"
    timeout_s: float = Field(ge=1, le=300)
    data_b64: str
    max_artifact_bytes: int = Field(default=5 * 1024 * 1024, ge=1, le=20 * 1024 * 1024)
    max_js_bytes: int = Field(default=200_000, ge=1, le=2_000_000)
    max_streams: int = Field(default=400, ge=1, le=10_000)


def _client():
    return docker.from_env()


def _authorize(token: str | None) -> None:
    if not TOKEN or not token or not secrets.compare_digest(token, TOKEN):
        raise HTTPException(status_code=401, detail="runner token inválido")


def _tar_bytes(name: str, data: bytes) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def _read_archive(chunks: Iterator[bytes], limit: int) -> bytes:
    stream = io.BytesIO()
    total = 0
    for chunk in chunks:
        total += len(chunk)
        if total > limit:
            raise ValueError("salida del worker supera el límite permitido")
        stream.write(chunk)
    stream.seek(0)
    with tarfile.open(fileobj=stream, mode="r:*") as archive:
        member = next((entry for entry in archive if entry.isfile()), None)
        if member is None or member.size > limit:
            raise ValueError("archivo de salida inválido")
        extracted = archive.extractfile(member)
        return extracted.read() if extracted else b""


def _put_sample(client, volume_name: str, data: bytes) -> None:
    helper = client.containers.create(
        BASE_IMAGE,
        command=["python", "-c", "import time; time.sleep(20)"],
        volumes={volume_name: {"bind": "/work", "mode": "rw"}},
    )
    try:
        helper.start()
        if not helper.put_archive("/work", _tar_bytes("sample.bin", data)):
            raise RuntimeError("no se pudo copiar la muestra al volumen aislado")
    finally:
        helper.remove(force=True)


def _prepare_output(client, volume_name: str) -> None:
    """El volumen nuevo pertenece a root; el worker solo puede escribir como uid 10001."""
    helper = client.containers.create(
        BASE_IMAGE,
        command=["python", "-c", "import os; os.chmod('/out', 0o777)"],
        user="0:0",
        volumes={volume_name: {"bind": "/out", "mode": "rw"}},
    )
    try:
        helper.start()
        result = helper.wait(timeout=20)
        if result.get("StatusCode") != 0:
            raise RuntimeError("no se pudo preparar el volumen de salida")
    finally:
        helper.remove(force=True)


def _run_worker(request: RunRequest) -> dict:
    if request.image not in ALLOWED or request.tool not in ALLOWED[request.image]:
        raise HTTPException(status_code=403, detail="imagen o herramienta no permitida")
    try:
        data = base64.b64decode(request.data_b64, validate=True)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="data_b64 inválido") from exc
    if not data or len(data) > MAX_REQUEST_BYTES:
        raise HTTPException(status_code=413, detail="muestra vacía o supera el límite del runner")

    try:
        client = _client()
    except DockerException as exc:
        raise HTTPException(status_code=503, detail=f"Docker no disponible: {exc}") from exc
    work = None
    out = None
    worker = None
    try:
        work = client.volumes.create(name=f"argos-work-{uuid.uuid4().hex}", labels={"argos.ephemeral": "true"})
        out = client.volumes.create(name=f"argos-out-{uuid.uuid4().hex}", labels={"argos.ephemeral": "true"})
        _put_sample(client, work.name, data)
        _prepare_output(client, out.name)
        worker = client.containers.create(
            request.image,
            command=[
                "python", "/opt/argos/entry.py", request.tool, "/work/sample.bin", "--type",
                request.detected_type, "--out", "/out",
            ],
            name=f"argos-{uuid.uuid4().hex[:12]}",
            network_mode="none",
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            pids_limit=128,
            mem_limit="768m",
            memswap_limit="768m",
            nano_cpus=1_000_000_000,
            ulimits=[docker.types.Ulimit(name="nofile", soft=256, hard=256)],
            tmpfs={"/tmp": "rw,noexec,nosuid,size=64m"},
            user="10001:10001",
            working_dir="/work",
            volumes={work.name: {"bind": "/work", "mode": "ro"}, out.name: {"bind": "/out", "mode": "rw"}},
            environment={
                "ARGOS_MAX_JS_BYTES": str(request.max_js_bytes),
                "ARGOS_MAX_STREAMS": str(request.max_streams),
                "ARGOS_MAX_ARTIFACT_BYTES": str(request.max_artifact_bytes),
            },
        )
        worker.start()
        status = worker.wait(timeout=request.timeout_s)
        try:
            raw = _read_archive(worker.get_archive("/out/result.json")[0], MAX_RESULT_BYTES)
            payload = json.loads(raw.decode("utf-8"))
        except (NotFound, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            logs = worker.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")[-800:]
            warning = f"worker sin result.json (exit {status.get('StatusCode')}): {exc}; {logs}"
            return {"status": "error", "warnings": [warning]}
        artifacts = []
        for item in payload.get("artifacts", []):
            rel = str(item.get("path", ""))
            if not rel or "/" in rel or "\\" in rel or ".." in rel:
                continue
            try:
                info = worker.get_archive(f"/out/{rel}")[1]
                size = int(info.get("size", 0))
                if size <= 0 or size > request.max_artifact_bytes:
                    continue
                artifact = _read_archive(worker.get_archive(f"/out/{rel}")[0], request.max_artifact_bytes)
            except (NotFound, ValueError):
                continue
            artifacts.append({
                "kind": str(item.get("kind", "blob")), "filename": str(item.get("filename", rel)),
                "note": str(item.get("note", "")), "data_b64": base64.b64encode(artifact).decode("ascii"),
            })
        payload["artifacts"] = artifacts
        return payload
    except docker.errors.APIError as exc:
        return {"status": "error", "warnings": [f"Docker rechazó el worker: {exc.explanation[:500]}"]}
    finally:
        if worker is not None:
            try:
                worker.remove(force=True)
            except DockerException:
                pass
        for volume in (work, out):
            if volume is None:
                continue
            try:
                volume.remove(force=True)
            except DockerException:
                pass


app = FastAPI(title="ARGOS sandbox runner", docs_url=None, redoc_url=None)


@app.get("/ready")
def ready() -> dict:
    """Sonda local de Compose; no expone estado ni operaciones del daemon."""
    return {"status": "ok"}


@app.get("/health")
def health(x_argos_runner_token: str | None = Header(default=None)) -> dict:
    _authorize(x_argos_runner_token)
    try:
        client = _client()
        images = {image: True for image in ALLOWED if client.images.list(name=image)}
        for image in ALLOWED:
            images.setdefault(image, False)
        return {"images": images, "isolation": "network=none, read-only, cap-drop=ALL"}
    except DockerException as exc:
        raise HTTPException(status_code=503, detail=f"Docker no disponible: {exc}") from exc


@app.post("/v1/run")
def run(request: RunRequest, x_argos_runner_token: str | None = Header(default=None)) -> dict:
    _authorize(x_argos_runner_token)
    return _run_worker(request)
