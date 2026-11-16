"""Tests del ejecutor Docker: endurecimiento del comando y ejecución real (opcional)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from core.policy import Budget
from tests.fixtures.pdf_factory import malicious_pdf
from tools.base import ToolContext
from tools.executors import docker_exec


def _settings():
    return SimpleNamespace(
        docker_binary="docker",
        docker_memory_mb=768,
        docker_cpus=1.0,
    )


def test_run_command_contains_hardening(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    sample = work / "sample.bin"
    sample.write_bytes(b"%PDF-1.7\n")
    out = tmp_path / "out"
    out.mkdir()

    cmd = docker_exec.build_run_command(
        image="argos/worker-pdf:0.1.0",
        tool="pdfid",
        sample_path=sample,
        out_dir=out,
        detected_type="pdf",
        settings=_settings(),
    )
    joined = " ".join(cmd)

    assert cmd[0] == "docker"
    assert cmd[1] == "run"
    assert "--rm" in cmd
    assert cmd[cmd.index("--network") + 1] == "none"
    assert "--read-only" in cmd
    assert cmd[cmd.index("--cap-drop") + 1] == "ALL"
    assert cmd[cmd.index("--security-opt") + 1] == "no-new-privileges:true"
    assert cmd[cmd.index("--user") + 1] == "10001:10001"
    assert "--pids-limit" in cmd
    assert "--memory" in cmd
    assert "/tmp:rw,noexec,nosuid" in joined
    assert ":/work:ro" in joined
    assert ":/out:rw" in joined
    assert "/var/run/docker.sock" not in joined
    assert cmd[-9:] == [
        "argos/worker-pdf:0.1.0",
        "python",
        "/opt/argos/entry.py",
        "pdfid",
        "/work/sample.bin",
        "--type",
        "pdf",
        "--out",
        "/out",
    ]


def test_run_command_mounts_use_forward_slashes(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    sample = work / "sample.bin"
    sample.write_bytes(b"x")
    out = tmp_path / "out"
    out.mkdir()
    cmd = docker_exec.build_run_command(
        image="img:1",
        tool="yara",
        sample_path=sample,
        out_dir=out,
        detected_type="unknown",
        settings=_settings(),
    )
    mounts = [cmd[i + 1] for i, token in enumerate(cmd) if token == "-v"]
    assert all("\\" not in mount for mount in mounts)
    assert any(mount.endswith(":/work:ro") for mount in mounts)


requires_docker = pytest.mark.skipif(
    not docker_exec.docker_available(), reason="daemon de Docker no disponible"
)


@requires_docker
def test_pdf_worker_runs_isolated() -> None:
    from core.settings import get_settings

    settings = get_settings()
    image = f"{settings.worker_image_prefix}-pdf:{settings.worker_image_tag}"
    if not docker_exec.image_available(image):
        pytest.skip(f"imagen no construida: {image}")

    ctx = ToolContext(
        sample_id="smp_docker_test",
        filename="sample.pdf",
        detected_type="pdf",
        data=malicious_pdf(),
    )
    out = docker_exec.run_in_docker(image=image, tool="pdfid", ctx=ctx, timeout_s=120)
    assert out.status in {"ok", "partial"}, out.warnings
    assert any(f.category == "javascript" for f in out.findings)
    assert "didier_pdfid" in out.engines or "qpdf" in out.engines


@requires_docker
def test_yara_worker_runs_isolated() -> None:
    from core.settings import get_settings

    settings = get_settings()
    image = f"{settings.worker_image_prefix}-yara:{settings.worker_image_tag}"
    if not docker_exec.image_available(image):
        pytest.skip(f"imagen no construida: {image}")

    ctx = ToolContext(
        sample_id="smp_docker_test",
        filename="sample.pdf",
        detected_type="pdf",
        data=malicious_pdf(),
    )
    out = docker_exec.run_in_docker(image=image, tool="yara", ctx=ctx, timeout_s=60)
    assert out.status == "ok"
    assert any(f.category == "yara" for f in out.findings)


@requires_docker
def test_sandbox_blocks_network_access() -> None:
    """El contenedor no debe poder resolver ni conectar a Internet."""
    import subprocess

    from core.settings import get_settings

    settings = get_settings()
    image = f"{settings.worker_image_prefix}-yara:{settings.worker_image_tag}"
    if not docker_exec.image_available(image):
        pytest.skip(f"imagen no construida: {image}")

    cmd = [
        settings.docker_binary,
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--user",
        "10001:10001",
        image,
        "python",
        "-c",
        "import socket; socket.create_connection(('1.1.1.1', 53), timeout=2)",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0


def test_docker_unavailable_does_not_crash(monkeypatch) -> None:
    monkeypatch.setattr(docker_exec, "docker_available", lambda: False)
    ctx = ToolContext("s", "x.pdf", "pdf", b"%PDF-1.7")
    with pytest.raises(docker_exec.DockerUnavailable):
        docker_exec.run_in_docker(image="nope:0", tool="pdfid", ctx=ctx, timeout_s=5)


def test_registry_docker_mode_without_image_reports_unavailable(monkeypatch) -> None:
    from core.settings import get_settings
    from tools import registry
    from tools.bootstrap import register_all

    register_all()
    settings = get_settings()
    monkeypatch.setattr(settings, "executor", "docker")
    monkeypatch.setattr(docker_exec, "docker_available", lambda: False)
    out = registry.run(
        "pdfid",
        ToolContext("s", "x.pdf", "pdf", b"%PDF-1.7"),
        Budget(),
    )
    assert out.status == "unavailable"
    assert "sandbox" in out.warnings[0].lower()
