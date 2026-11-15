"""Triage determinista: firma real, hashes, entropía y coherencia de extensión."""

from __future__ import annotations

import io
import zipfile

from core.hashing import entropy, md5_bytes, printable_ratio, sha256_bytes
from tools.base import FindingDraft, ToolContext, ToolOutput

MAGIC = [
    (b"%PDF-", "pdf", "application/pdf"),
    (b"PK\x03\x04", "zip", "application/zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "application/x-ole-storage"),
    (b"MZ", "pe", "application/vnd.microsoft.portable-executable"),
    (b"\x7fELF", "elf", "application/x-elf"),
    (b"Rar!\x1a\x07", "rar", "application/vnd.rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "application/x-7z-compressed"),
    (b"\x1f\x8b", "gzip", "application/gzip"),
]

JS_HINTS = (b"function ", b"eval(", b"unescape(", b"ActiveXObject", b"WScript", b"document.write")
OFFICE_EXT = {"doc", "docx", "docm", "dotm", "xls", "xlsx", "xlsm", "xltm", "ppt", "pptx", "pptm"}
SHELLCODE_EXT = {"bin", "raw", "sc", "shellcode", "dat"}


def _zip_subtype(data: bytes) -> tuple[str, str, list[str]]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        return "zip", "application/zip", []
    joined = " ".join(names).lower()
    has_vba = any(n.lower().endswith("vbaproject.bin") for n in names)
    if has_vba or joined.startswith(("word/", "xl/", "ppt/")) and any(
        n.lower().startswith(("word/", "xl/", "ppt/")) for n in names
    ):
        if "xl/" in joined:
            return "office", "application/vnd.ms-excel.sheet.macroEnabled", names
        if "ppt/" in joined:
            return "office", "application/vnd.ms-powerpoint.presentation.macroEnabled", names
        return "office", "application/vnd.ms-word.document.macroEnabled", names
    return "zip", "application/zip", names


def detect(data: bytes, filename: str) -> tuple[str, str, list[str]]:
    head = data[:4096]
    for magic, kind, mime in MAGIC:
        if head.startswith(magic):
            if kind == "zip":
                return _zip_subtype(data)
            if kind == "ole":
                return "office", "application/x-ole-storage", []
            if kind == "elf":
                return "elf", mime, []
            return kind, mime, []

    text_ratio = printable_ratio(head) if head else 0.0
    lowered = head.lower()
    if text_ratio > 0.85:
        if any(h.lower() in lowered for h in JS_HINTS) or b"<script" in lowered:
            return "javascript", "text/javascript", []
        if b"<html" in lowered or b"<!doctype html" in lowered:
            return "html", "text/html", []

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in SHELLCODE_EXT and text_ratio < 0.6:
        return "shellcode", "application/octet-stream", []
    if len(data) < 1_000_000 and text_ratio < 0.55 and entropy(data) > 6.5:
        return "shellcode", "application/octet-stream", []
    return "unknown", "application/octet-stream", []


def triage(ctx: ToolContext) -> ToolOutput:
    data = ctx.data
    detected, mime, zip_names = detect(data, ctx.filename)
    sha256, md5 = sha256_bytes(data), md5_bytes(data)
    ext = ctx.filename.rsplit(".", 1)[-1].lower() if "." in ctx.filename else ""
    ent = entropy(data)

    findings: list[FindingDraft] = [
        FindingDraft(
            category="type",
            description=f"Tipo real detectado: {detected} ({mime}); {len(data)} bytes",
            suspicious=False,
            score=0.0,
        )
    ]
    warnings: list[str] = []

    if ext and detected not in {"unknown", "zip", "html", "elf"}:
        coherent = (
            (detected == "pdf" and ext == "pdf")
            or (detected == "office" and ext in OFFICE_EXT)
            or (detected == "javascript" and ext in {"js", "jse", "vbs", "vbe", "wsf", "hta"})
            or (detected == "pe" and ext in {"exe", "dll", "sys", "scr", "cpl"})
            or (detected == "shellcode" and ext in SHELLCODE_EXT)
        )
        if not coherent:
            findings.append(
                FindingDraft(
                    category="extension_mismatch",
                    description=f"La extensión '.{ext}' no corresponde al contenido real ({detected})",
                    suspicious=True,
                    score=1.5,
                )
            )

    if ctx.filename.count(".") >= 2:
        findings.append(
            FindingDraft(
                category="double_extension",
                description="Nombre de archivo con doble extensión",
                suspicious=True,
                score=1.0,
            )
        )

    if len(data) > 4096 and ent > 7.2:
        findings.append(
            FindingDraft(
                category="entropy",
                description=f"Entropía alta ({ent:.2f}/8): contenido comprimido, cifrado u ofuscado",
                suspicious=True,
                score=0.8,
            )
        )

    if detected == "elf":
        warnings.append("Binarios ELF no soportados en el MVP; se continúa solo con triage")
    if detected in {"zip", "html", "rar", "7z", "gzip"}:
        warnings.append(f"Contenedor '{detected}' reconocido pero sin analizador en el MVP")

    return ToolOutput(
        status="ok" if detected != "unknown" else "partial",
        findings=findings,
        warnings=warnings,
        data={
            "detected_type": detected,
            "mime": mime,
            "sha256": sha256,
            "md5": md5,
            "size": len(data),
            "extension": ext,
            "entropy": round(ent, 3),
            "printable_ratio": round(printable_ratio(data), 3),
            "header_hex": data[:16].hex(),
            "zip_entries": zip_names[:40],
        },
    )
