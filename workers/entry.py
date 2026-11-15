#!/usr/bin/env python3
"""Entrada única de los workers del sandbox ARGOS.

Se ejecuta dentro del contenedor:

    python /opt/argos/entry.py <tool> /work/sample.bin --type pdf --out /out

Nunca imprime el resultado por stdout (los parsers pueden escribir ahí): lo deja
en ``/out/result.json``. Los artefactos van a ``/out/<archivo>`` y se referencian
en el manifiesto.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, "/opt/argos")

from tools.base import ToolContext, ToolOutput  # noqa: E402

TOOLS = {}


def _load_tools() -> None:
    from tools.adapters import js_analyzer, office, pdf_parser, pdfid, shellcode, yara_scan

    TOOLS.update(
        {
            "pdfid": pdfid.scan,
            "pdf_parser": pdf_parser.parse,
            "office": office.scan,
            "js": js_analyzer.analyze,
            "binary": shellcode.scan,
            "yara": yara_scan.scan,
        }
    )


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _artifact_name(index: int, kind: str, filename: str) -> str:
    suffix = Path(filename).suffix.lower()[:12]
    safe_kind = "".join(c for c in kind if c.isalnum() or c in "-_")[:20] or "blob"
    if not suffix or len(suffix) > 12:
        suffix = ".bin"
    return f"artifact_{index:04d}_{safe_kind}{suffix}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tool")
    parser.add_argument("sample")
    parser.add_argument("--type", default="unknown")
    parser.add_argument("--out", default="/out")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    result_path = out_dir / "result.json"

    try:
        data = Path(args.sample).read_bytes()
        _load_tools()
        if args.tool not in TOOLS:
            raise SystemExit(f"herramienta desconocida: {args.tool}")

        ctx = ToolContext(
            sample_id="sandbox",
            filename=Path(args.sample).name,
            detected_type=args.type,
            data=data,
            meta={
                "max_js_bytes": _env_int("ARGOS_MAX_JS_BYTES", 200_000),
                "max_streams": _env_int("ARGOS_MAX_STREAMS", 400),
            },
        )
        output: ToolOutput = TOOLS[args.tool](ctx)

        from workers.enrich import enrich  # import tardío: depende de la imagen

        extra = enrich(args.tool, Path(args.sample), output, out_dir)
        payload = _serialize(output, out_dir, extra)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - el worker siempre responde JSON
        payload = {
            "status": "error",
            "findings": [],
            "artifacts": [],
            "data": {},
            "warnings": [f"worker: {type(exc).__name__}: {exc}"],
            "metrics": {},
            "engines": {},
            "engine_version": "",
        }

    result_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return 0


def _serialize(output: ToolOutput, out_dir: Path, extra: dict | None) -> dict:
    findings = [
        {
            "category": f.category,
            "description": f.description,
            "suspicious": f.suspicious,
            "score": f.score,
            "object_id": f.object_id,
            "raw_ref": f.raw_ref,
        }
        for f in output.findings
    ]
    artifacts: list[dict] = []
    max_bytes = _env_int("ARGOS_MAX_ARTIFACT_BYTES", 5 * 1024 * 1024)

    for index, artifact in enumerate(output.artifacts):
        if not artifact.data or len(artifact.data) > max_bytes:
            continue
        name = _artifact_name(index, artifact.kind, artifact.filename)
        (out_dir / name).write_bytes(artifact.data)
        artifacts.append(
            {
                "kind": artifact.kind,
                "filename": artifact.filename,
                "note": artifact.note,
                "path": name,
                "size": len(artifact.data),
            }
        )

    data = dict(output.data)
    engines = dict(output.engines)
    warnings = list(output.warnings)
    metrics = dict(output.metrics)
    status = output.status

    if extra:
        findings.extend(extra.get("findings", []))
        artifacts.extend(extra.get("artifacts", []))
        data.update(extra.get("data", {}))
        engines.update(extra.get("engines", {}))
        warnings.extend(extra.get("warnings", []))
        metrics.update(extra.get("metrics", {}))
        if extra.get("status"):
            status = extra["status"]

    return {
        "status": status,
        "findings": findings,
        "artifacts": artifacts,
        "data": data,
        "warnings": warnings[:20],
        "metrics": metrics,
        "engines": engines,
        "engine_version": output.tool_version,
    }


if __name__ == "__main__":
    raise SystemExit(main())
