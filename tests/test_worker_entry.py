"""Contrato del worker del sandbox, ejecutado sin Docker (entry.py -> result.json)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run_worker(tool: str, sample: bytes, *, detected: str, tmp_path: Path) -> dict:
    sample_path = tmp_path / "sample.bin"
    sample_path.write_bytes(sample)
    out_dir = tmp_path / "out"
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "workers" / "entry.py"),
            tool,
            str(sample_path),
            "--type",
            detected,
            "--out",
            str(out_dir),
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    result = out_dir / "result.json"
    assert result.is_file(), proc.stderr
    return json.loads(result.read_text(encoding="utf-8"))


def test_worker_pdf_parser_manifest(tmp_path: Path) -> None:
    from tests.fixtures.pdf_factory import malicious_pdf

    payload = _run_worker("pdf_parser", malicious_pdf(with_embedded=True), detected="pdf", tmp_path=tmp_path)
    assert payload["status"] in {"ok", "partial"}
    assert payload["findings"]
    kinds = {a["kind"] for a in payload["artifacts"]}
    assert "javascript" in kinds
    for artifact in payload["artifacts"]:
        assert (tmp_path / "out" / artifact["path"]).is_file()
        assert artifact["size"] > 0


def test_worker_office_extracts_vba(tmp_path: Path) -> None:
    from tests.fixtures.pdf_factory import docm_bytes

    payload = _run_worker("office", docm_bytes(), detected="office", tmp_path=tmp_path)
    assert payload["status"] in {"ok", "partial"}
    categories = {f["category"] for f in payload["findings"]}
    assert "macro" in categories
    assert any(a["kind"] == "vba" for a in payload["artifacts"])


def test_worker_yara(tmp_path: Path) -> None:
    from tests.fixtures.pdf_factory import malicious_pdf

    payload = _run_worker("yara", malicious_pdf(), detected="pdf", tmp_path=tmp_path)
    assert payload["status"] == "ok"
    assert any(f["category"] == "yara" for f in payload["findings"])


def test_worker_unknown_tool_fails_cleanly(tmp_path: Path) -> None:
    out = tmp_path / "out"
    sample = tmp_path / "x.bin"
    sample.write_bytes(b"%PDF-1.7")
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "workers" / "entry.py"),
            "does_not_exist",
            str(sample),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        timeout=60,
    )
    assert proc.returncode != 0
