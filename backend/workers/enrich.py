"""Enriquecimiento con herramientas externas dentro del contenedor.

Cada función es best-effort: si la herramienta no está en la imagen, se ignora y
se deja constancia en ``warnings``/``engines``. Nunca lanza hacia el worker.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from tools.base import ToolOutput


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, f"{type(exc).__name__}: {exc}"


def _pkg_version(name: str) -> str:
    try:
        from importlib.metadata import version

        return version(name)
    except Exception:  # noqa: BLE001
        return ""


def _add_artifact(out_dir: Path, name: str, data: bytes, kind: str, filename: str, note: str) -> dict:
    path = out_dir / name
    path.write_bytes(data[: 5 * 1024 * 1024])
    return {"kind": kind, "filename": filename, "note": note, "path": name, "size": path.stat().st_size}


# --------------------------------------------------------------------------- PDF
def _pdf(sample: Path, output: ToolOutput, out_dir: Path) -> dict:
    findings: list[dict] = []
    data: dict = {}
    engines: dict = {}
    warnings: list[str] = []

    pdfid = Path("/opt/didier/pdfid.py")
    if pdfid.is_file():
        code, text = _run(["python", str(pdfid), "-a", str(sample)], timeout=45)
        tokens: dict[str, int] = {}
        for line in text.splitlines():
            match = re.match(r"\s*(/[A-Za-z0-9]+)\s+(\d+)\s*$", line)
            if match:
                tokens[match.group(1)] = int(match.group(2))
        data["didier_pdfid"] = {"exit": code, "tokens": tokens, "output": text[-1200:]}
        engines["didier_pdfid"] = "suite"
        suspicious = tokens.get("/JavaScript", 0) + tokens.get("/OpenAction", 0) + tokens.get("/Launch", 0)
        findings.append(
            {
                "category": "pdf_tokens",
                "description": f"PDFiD (Didier Stevens): {sum(tokens.values())} tokens, "
                f"{suspicious} de riesgo entre /JS, /OpenAction y /Launch",
                "suspicious": suspicious > 0,
                "score": 1.5 if suspicious else 0.0,
            }
        )
    else:
        warnings.append("pdfid.py de Didier Stevens no está en la imagen")

    qpdf = shutil.which("qpdf")
    if qpdf:
        code, text = _run([qpdf, "--check", str(sample)], timeout=30)
        data["qpdf"] = {"exit": code, "ok": code == 0, "output": text[-800:]}
        engines["qpdf"] = _run([qpdf, "--version"], timeout=10)[1].splitlines()[0][:40]
        if code not in (0, 3):  # 3 = warnings recuperables
            findings.append(
                {
                    "category": "pdf_structure",
                    "description": f"qpdf reporta errores estructurales (exit {code}): {text.strip()[:200]}",
                    "suspicious": True,
                    "score": 1.0,
                }
            )

    return {"findings": findings, "data": data, "engines": engines, "warnings": warnings}


# ------------------------------------------------------------------------ Office
def _office(sample: Path, output: ToolOutput, out_dir: Path) -> dict:
    findings: list[dict] = []
    data: dict = {}
    engines: dict = {}
    warnings: list[str] = []
    artifacts: list[dict] = []

    try:
        from oletools.olevba import VBA_Parser
    except ImportError as exc:  # pragma: no cover - depende de la imagen
        return {"warnings": [f"oletools no disponible en la imagen: {exc}"]}

    try:
        parser = VBA_Parser(str(sample))
        engines["oletools"] = _pkg_version("oletools")
        if parser.detect_vba_macros():
            macros = []
            for index, (_filename, stream_path, vba_filename, vba_code) in enumerate(
                parser.extract_macros()
            ):
                code = vba_code or ""
                autoexec = [
                    token
                    for token in ("AutoOpen", "Auto_Open", "Document_Open", "Workbook_Open", "AutoExec")
                    if token.lower() in code.lower()
                ]
                macros.append(
                    {
                        "file": vba_filename,
                        "stream": stream_path,
                        "size": len(code),
                        "autoexec": autoexec,
                    }
                )
                if index < 4 and code:
                    name = (
                        f"macro_{index:02d}_"
                        f"{re.sub(r'[^A-Za-z0-9_.-]', '_', vba_filename)[:40]}.vba"
                    )
                    artifacts.append(
                        _add_artifact(
                            out_dir,
                            name,
                            code.encode("utf-8", "replace"),
                            "vba",
                            vba_filename,
                            "Macro extraída por olevba",
                        )
                    )
                findings.append(
                    {
                        "category": "macro",
                        "description": f"olevba extrajo macro '{vba_filename}' ({len(code)} bytes)"
                        + (f" con {', '.join(autoexec)}" if autoexec else ""),
                        "suspicious": True,
                        "score": 3.5 if autoexec else 2.5,
                    }
                )
            data["olevba"] = {"macros": macros, "count": len(macros)}
        else:
            data["olevba"] = {"macros": [], "count": 0}
    except Exception as exc:  # noqa: BLE001 - oletools falla con muestras raras
        warnings.append(f"olevba falló: {type(exc).__name__}: {exc}")
    finally:
        try:
            parser.close()
        except Exception:  # noqa: BLE001
            pass

    return {
        "findings": findings,
        "artifacts": artifacts,
        "data": data,
        "engines": engines,
        "warnings": warnings,
    }


# -------------------------------------------------------------------- JavaScript
def _js(sample: Path, output: ToolOutput, out_dir: Path) -> dict:
    findings: list[dict] = []
    data: dict = {}
    engines: dict = {}
    warnings: list[str] = []
    artifacts: list[dict] = []
    status = ""

    node = shutil.which("node")
    boxjs = Path("/opt/boxjs/node_modules/.bin/box-js")
    if not node or not boxjs.is_file():
        warnings.append("box-js no está disponible en la imagen; solo análisis estático")
        return {"findings": findings, "data": data, "engines": engines, "warnings": warnings}

    with tempfile.TemporaryDirectory() as tmp:
        code, text = _run(
            [
                str(node),
                str(boxjs),
                str(sample),
                "--output-dir",
                tmp,
                "--loglevel",
                "warning",
                "--no-kill",
                "--no-shell-error",
            ],
            timeout=90,
        )

        results_dir = next(iter(Path(tmp).glob("*.results")), None)
        iocs: list[dict] = []
        ioc_file = results_dir / "IOC.json" if results_dir else None
        if ioc_file and ioc_file.is_file():
            try:
                iocs = json.loads(ioc_file.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                iocs = []

        for item in iocs if isinstance(iocs, list) else []:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("type", ""))
            value = item.get("value")
            if kind.lower() in {"run", "shell", "exec"}:
                command = value.get("command") if isinstance(value, dict) else str(value)
                if command:
                    findings.append(
                        {
                            "category": "emulation",
                            "description": f"box-js observó la ejecución de: {str(command)[:200]}",
                            "suspicious": True,
                            "score": 3.5,
                        }
                    )
            elif kind.lower() in {"url", "domain", "ip", "file"} and value:
                findings.append(
                    {
                        "category": "emulation",
                        "description": f"box-js observó acceso a {kind}: {str(value)[:160]}",
                        "suspicious": True,
                        "score": 2.0,
                    }
                )

        dropped: list[str] = []
        metadata = {"ioc.json", "analysis.log", "snippets.json"}
        if results_dir:
            for path in sorted(results_dir.rglob("*")):
                if not path.is_file() or path.name.lower() in metadata:
                    continue
                if path.stat().st_size > 2 * 1024 * 1024:
                    continue
                dropped.append(path.name)
                if len(dropped) <= 5:
                    artifacts.append(
                        _add_artifact(
                            out_dir,
                            f"boxjs_{len(dropped):02d}_{path.name[:60]}",
                            path.read_bytes(),
                            "dropped",
                            path.name,
                            "Archivo generado durante la emulación box-js",
                        )
                    )

        data["boxjs"] = {
            "exit": code,
            "iocs": iocs[:20] if isinstance(iocs, list) else [],
            "dropped_files": dropped[:20],
            "output": text[-1200:],
        }
        engines["box_js"] = "instalado"
        if iocs or dropped:
            findings.append(
                {
                    "category": "emulation",
                    "description": f"box-js emuló el script: {len(iocs)} IOCs y {len(dropped)} "
                    f"archivos generados",
                    "suspicious": True,
                    "score": 2.5,
                }
            )
        if code != 0:
            warnings.append(f"box-js terminó con código {code}; emulación parcial")
            status = "partial"

    return {
        "findings": findings,
        "artifacts": artifacts,
        "data": data,
        "engines": engines,
        "warnings": warnings,
        "status": status,
    }


# ----------------------------------------------------------------------- Binario
def _binary(sample: Path, output: ToolOutput, out_dir: Path) -> dict:
    findings: list[dict] = []
    data: dict = {}
    engines: dict = {}
    warnings: list[str] = []

    try:
        import lief

        binary = lief.parse(str(sample))
        if binary is not None:
            info = {
                "format": str(getattr(binary, "format", "?")).split(".")[-1],
                "entrypoint": hex(getattr(binary, "entrypoint", 0) or 0),
                "sections": len(getattr(binary, "sections", []) or []),
            }
            data["lief"] = info
            engines["lief"] = _pkg_version("lief")
            findings.append(
                {
                    "category": "binary_format",
                    "description": f"LIEF: formato {info['format']}, entrypoint {info['entrypoint']}, "
                    f"{info['sections']} secciones",
                    "suspicious": False,
                    "score": 0.0,
                }
            )
        else:
            warnings.append("LIEF no reconoció un formato ejecutable (puede ser shellcode crudo)")
    except ImportError:
        warnings.append("LIEF no está en la imagen")
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"LIEF falló: {type(exc).__name__}: {exc}")

    objdump = shutil.which("objdump")
    if objdump and not data.get("lief"):
        code, text = _run([objdump, "-D", "-b", "binary", "-m", "i386", str(sample)], timeout=30)
        count = sum(1 for line in text.splitlines() if re.match(r"\s*[0-9a-f]+:\s", line))
        data["objdump"] = {"exit": code, "instructions": count}
        engines["objdump"] = _run([objdump, "--version"], timeout=10)[1].splitlines()[0][:40]
        findings.append(
            {
                "category": "disassembly",
                "description": f"objdump desensambló {count} instrucciones (x86)",
                "suspicious": False,
                "score": 0.3,
            }
        )

    return {"findings": findings, "data": data, "engines": engines, "warnings": warnings}


ENRICHERS = {"pdfid": _pdf, "pdf_parser": _pdf, "office": _office, "js": _js, "binary": _binary}


def enrich(tool: str, sample: Path, output: ToolOutput, out_dir: Path) -> dict | None:
    fn = ENRICHERS.get(tool)
    if fn is None:
        return None
    try:
        return fn(sample, output, out_dir)
    except Exception as exc:  # noqa: BLE001 - nunca tumbar el worker
        return {"warnings": [f"enriquecimiento falló: {type(exc).__name__}: {exc}"], "data": {}}
