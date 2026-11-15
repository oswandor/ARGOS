"""Análisis estático de documentos Office (OLE y OOXML con macros).

No usa Word/Excel. Extrae ``vbaProject.bin`` de los ZIP (docm/xlsm) y detecta
macros/objetos embebidos en OLE con olefile.
"""

from __future__ import annotations

import io
import re
import zipfile

from core.hashing import sha256_bytes
from tools.base import ArtifactDraft, FindingDraft, ToolContext, ToolOutput

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

AUTOEXEC = (
    "AutoOpen",
    "Auto_Open",
    "Document_Open",
    "Workbook_Open",
    "Workbook_Activate",
    "AutoClose",
    "AutoExec",
    "DocumentBeforeClose",
)

VBA_APIS = (
    "Shell",
    "CreateObject",
    "WScript.Shell",
    "powershell",
    "cmd.exe",
    "URLDownloadToFile",
    "ADODB.Stream",
    "MSXML2.XMLHTTP",
    "Environ",
    "GetObject",
    "ShellExecute",
    "Chr(",
    "StrReverse",
)

DECLARATOR = re.compile(r"(?i)\b(?:Sub|Function|Private Sub|Public Sub)\s+([A-Za-z_]\w*)")


def _zip_scan(data: bytes) -> tuple[list[dict], list[ArtifactDraft], list[str]]:
    entries: list[dict] = []
    artifacts: list[ArtifactDraft] = []
    warnings: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist()[:200]:
                entries.append({"name": info.filename, "size": info.file_size})
                lower = info.filename.lower()
                if lower.endswith("vbaproject.bin"):
                    blob = zf.read(info)
                    artifacts.append(
                        ArtifactDraft(
                            kind="vba",
                            data=blob,
                            filename=info.filename.split("/")[-1],
                            note="Proyecto VBA embebido",
                        )
                    )
                elif "embeddings/" in lower or "oleobject" in lower:
                    try:
                        blob = zf.read(info)
                    except (RuntimeError, zipfile.BadZipFile):
                        continue
                    if 0 < len(blob) <= 5 * 1024 * 1024:
                        artifacts.append(
                            ArtifactDraft(
                                kind="embedded",
                                data=blob,
                                filename=info.filename.split("/")[-1],
                                note="Objeto embebido OOXML",
                            )
                        )
    except zipfile.BadZipFile as exc:
        warnings.append(f"ZIP inválido: {exc}")
    return entries, artifacts, warnings


def _ole_scan(data: bytes) -> tuple[list[str], list[ArtifactDraft], list[str]]:
    streams: list[str] = []
    artifacts: list[ArtifactDraft] = []
    warnings: list[str] = []
    try:
        import olefile

        ole = olefile.OleFileIO(io.BytesIO(data))
        paths = ["/".join(p) for p in ole.listdir()]
        streams = paths[:200]
        for path in paths:
            low = path.lower()
            if low.endswith("vbaproject.bin") or low.endswith("_vba_project"):
                blob = ole.openstream(path).read()
                artifacts.append(
                    ArtifactDraft(
                        kind="vba",
                        data=blob,
                        filename=path.split("/")[-1],
                        note="Proyecto VBA en contenedor OLE",
                    )
                )
            elif "objectpool" in low or low.endswith("ole10native"):
                try:
                    blob = ole.openstream(path).read()
                except OSError:
                    continue
                if 0 < len(blob) <= 5 * 1024 * 1024:
                    artifacts.append(
                        ArtifactDraft(
                            kind="embedded",
                            data=blob,
                            filename=path.split("/")[-1],
                            note="Objeto embebido OLE",
                        )
                    )
    except Exception as exc:  # noqa: BLE001 - olefile es best-effort
        warnings.append(f"OLE no inspeccionable: {type(exc).__name__}: {exc}")
    return streams, artifacts, warnings


def scan(ctx: ToolContext) -> ToolOutput:
    data = ctx.data
    findings: list[FindingDraft] = []
    warnings: list[str] = []
    entries: list[dict] = []
    streams: list[str] = []
    artifacts: list[ArtifactDraft] = []
    container = "desconocido"

    if data.startswith(b"PK\x03\x04"):
        container = "ooxml"
        entries, artifacts, z_warn = _zip_scan(data)
        warnings.extend(z_warn)
    elif data.startswith(OLE_MAGIC):
        container = "ole"
        streams, artifacts, o_warn = _ole_scan(data)
        warnings.extend(o_warn)
    else:
        return ToolOutput(
            status="error",
            warnings=["El archivo no es un contenedor Office reconocible (ZIP/OLE)"],
        )

    vba_blobs = [a for a in artifacts if a.kind == "vba"]
    embedded = [a for a in artifacts if a.kind == "embedded"]

    haystack = data[:20_000_000]
    vba_text = b""
    for artifact in vba_blobs:
        vba_text += artifact.data
    haystack = data + vba_text

    autoexec_hits = [token for token in AUTOEXEC if re.search(token.encode(), haystack, re.I)]
    api_hits = [api for api in VBA_APIS if re.search(re.escape(api).encode(), haystack, re.I)]
    procedures = DECLARATOR.findall(vba_text.decode("latin-1", errors="replace"))[:20] if vba_text else []

    if vba_blobs or any("vba" in s.lower() for s in streams):
        findings.append(
            FindingDraft(
                category="macro",
                description=f"Proyecto VBA presente ({len(vba_blobs)} artefacto(s), {len(vba_text)} bytes)",
                suspicious=True,
                score=3.0,
            )
        )
    if autoexec_hits:
        findings.append(
            FindingDraft(
                category="autoexec",
                description="Macros de ejecución automática: " + ", ".join(autoexec_hits[:6]),
                suspicious=True,
                score=3.0,
            )
        )
    if api_hits:
        findings.append(
            FindingDraft(
                category="macro_api",
                description="APIs peligrosas en el documento: " + ", ".join(api_hits[:8]),
                suspicious=True,
                score=2.5,
            )
        )
    if embedded:
        findings.append(
            FindingDraft(
                category="embedded",
                description=f"{len(embedded)} objeto(s) embebido(s) en el documento",
                suspicious=True,
                score=2.0,
            )
        )

    return ToolOutput(
        findings=findings,
        artifacts=artifacts,
        warnings=warnings,
        data={
            "container": container,
            "entries": entries[:60],
            "ole_streams": streams[:60],
            "vba_sha256": [sha256_bytes(a.data) for a in vba_blobs],
            "vba_size": len(vba_text),
            "procedures": procedures,
            "autoexec": autoexec_hits,
            "suspicious_apis": api_hits,
            "embedded_count": len(embedded),
            "note": "Análisis estático; las macros no se ejecutaron",
        },
        metrics={"vba_bytes": float(len(vba_text)), "artifacts": float(len(artifacts))},
    )
