"""pdf-parser nativo: objetos, streams comprimidos, JavaScript y archivos embebidos.

No ejecuta nada y no depende de librerías PDF externas: analiza los bytes tal
como están, incluyendo PDFs malformados o con xref roto.
"""

from __future__ import annotations

import re
import zlib

from core.hashing import sha256_bytes
from tools.base import ArtifactDraft, FindingDraft, ToolContext, ToolOutput

OBJ_RE = re.compile(rb"(?<![0-9])(\d{1,10})\s+(\d{1,5})\s+obj\b(.*?)\bendobj", re.S)
STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)
HEX_RE = re.compile(rb"<([0-9A-Fa-f\s]{2,})>")
JS_REF_RE = re.compile(rb"/JS\s+(\d{1,10})\s+\d{1,5}\s+R")
NAME_RE = re.compile(rb"/(?:F|UF)\s*\(([^)]{0,120})\)")

JS_MARKERS = (
    b"function",
    b"eval(",
    b"unescape(",
    b"String.fromCharCode",
    b"ActiveXObject",
    b"WScript",
    b"app.",
    b"document.",
    b"var ",
    b"while(",
    b"for(",
)

MAX_JS_ARTIFACTS = 8
MAX_EMBEDDED = 4
MAX_PREVIEW = 400


def _literal_strings(data: bytes) -> list[bytes]:
    """Extrae cadenas literales ``(...)`` con escapes PDF."""
    out: list[bytes] = []
    i, n = 0, len(data)
    while i < n:
        if data[i] != 0x28:  # '('
            i += 1
            continue
        depth, j, buf = 1, i + 1, bytearray()
        while j < n and depth:
            c = data[j]
            if c == 0x5C:  # backslash
                nxt = data[j + 1 : j + 2]
                simple = {b"n": 10, b"r": 13, b"t": 9, b"b": 8, b"f": 12}
                if nxt in (b"(", b")", b"\\"):
                    buf.append(nxt[0])
                    j += 2
                elif nxt in simple:
                    buf.append(simple[nxt])
                    j += 2
                elif nxt == b"\n":
                    j += 2
                elif nxt.isdigit():
                    m = re.match(rb"[0-7]{1,3}", data[j + 1 : j + 4])
                    if m:
                        buf.append(int(m.group(0), 8) & 0xFF)
                        j += 1 + len(m.group(0))
                    else:
                        j += 2
                else:
                    buf.append(nxt[0] if nxt else 0)
                    j += 2
            elif c == 0x28:
                depth += 1
                buf.append(c)
                j += 1
            elif c == 0x29:
                depth -= 1
                j += 1
            else:
                buf.append(c)
                j += 1
        out.append(bytes(buf))
        i = j
    return out


def _hex_strings(data: bytes) -> list[bytes]:
    out: list[bytes] = []
    for m in HEX_RE.finditer(data):
        raw = re.sub(rb"\s", b"", m.group(1))
        if len(raw) % 2:
            raw += b"0"
        try:
            out.append(bytes.fromhex(raw.decode("ascii")))
        except (ValueError, UnicodeDecodeError):
            continue
    return out


def _looks_like_js(blob: bytes) -> bool:
    if len(blob) < 24:
        return False
    hits = sum(1 for marker in JS_MARKERS if marker in blob)
    return hits >= 2 or (b"function" in blob and len(blob) > 120)


def _inflate(raw: bytes) -> bytes | None:
    for wbits in (15, -15, 31):
        try:
            return zlib.decompress(raw, wbits)
        except zlib.error:
            continue
    try:
        return zlib.decompressobj().decompress(raw)
    except zlib.error:
        return None


def _preview(blob: bytes) -> str:
    text = blob[:MAX_PREVIEW].decode("latin-1", errors="replace")
    return "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text).strip()


def parse(ctx: ToolContext) -> ToolOutput:
    data = ctx.data
    objects = list(OBJ_RE.finditer(data))
    bodies: dict[int, bytes] = {int(m.group(1)): m.group(3) for m in objects}

    findings: list[FindingDraft] = []
    artifacts: list[ArtifactDraft] = []
    warnings: list[str] = []
    js_entries: list[dict] = []
    embedded_entries: list[dict] = []
    seen_js: set[str] = set()
    stream_count = 0
    decoded_count = 0

    def add_js(blob: bytes, object_id: str, origin: str) -> None:
        nonlocal js_entries
        if len(artifacts) >= MAX_JS_ARTIFACTS + MAX_EMBEDDED or len(js_entries) >= MAX_JS_ARTIFACTS:
            return
        digest = sha256_bytes(blob)
        if digest in seen_js or len(blob) > ctx.meta.get("max_js_bytes", 200_000):
            return
        seen_js.add(digest)
        obj_num = object_id.split()[0] if object_id else "0"
        artifacts.append(
            ArtifactDraft(
                kind="javascript",
                data=blob,
                filename=f"pdf_object_{obj_num}.js",
                note=f"Extraído de {origin}",
            )
        )
        js_entries.append(
            {
                "object_id": object_id,
                "origin": origin,
                "size": len(blob),
                "sha256": digest,
                "preview": _preview(blob),
            }
        )
        findings.append(
            FindingDraft(
                category="javascript",
                description=(
                    f"JavaScript extraído del objeto {object_id} ({len(blob)} bytes, "
                    f"sha256 {digest[:16]}…)"
                ),
                suspicious=True,
                score=2.5,
                object_id=object_id,
                raw_ref=f"sha256:{digest}",
            )
        )

    # 1) Objetos con /JS o /JavaScript
    for num, body in bodies.items():
        if b"/JS" not in body and b"/JavaScript" not in body:
            continue
        object_id = f"{num} 0"
        chunks = _literal_strings(body) + _hex_strings(body)
        for blob in chunks:
            if _looks_like_js(blob):
                add_js(blob, object_id, "objeto /JS")
        for ref in JS_REF_RE.findall(body):
            target = bodies.get(int(ref))
            if target:
                for blob in _literal_strings(target) + _hex_strings(target):
                    if _looks_like_js(blob):
                        add_js(blob, f"{int(ref)} 0", "referencia /JS")

    # 1b) Acción automática /OpenAction (puede estar en el catálogo, sin /JS)
    for num, body in bodies.items():
        if b"/OpenAction" in body:
            object_id = f"{num} 0"
            findings.append(
                FindingDraft(
                    category="pdf_action",
                    description=f"/OpenAction en el objeto {object_id}: acción automática al abrir",
                    suspicious=True,
                    score=2.0,
                    object_id=object_id,
                )
            )

    # 2) Streams (comprimidos o no) con JavaScript incrustado
    for num, body in bodies.items():
        for sm in STREAM_RE.finditer(body):
            stream_count += 1
            if stream_count > ctx.meta.get("max_streams", 400):
                warnings.append("Límite de streams alcanzado; análisis parcial")
                break
            raw = sm.group(1)
            payload = raw
            if b"/FlateDecode" in body:
                inflated = _inflate(raw)
                if inflated is None:
                    continue
                payload = inflated
                decoded_count += 1
            if _looks_like_js(payload):
                add_js(payload, f"{num} 0", "stream comprimido" if payload is not raw else "stream")

    # 3) Archivos embebidos
    for num, body in bodies.items():
        if b"/EmbeddedFile" not in body and b"/Filespec" not in body:
            continue
        if len(embedded_entries) >= MAX_EMBEDDED:
            break
        name_match = NAME_RE.search(body)
        filename = (
            name_match.group(1).decode("latin-1", errors="replace") if name_match else f"embedded_{num}.bin"
        )
        blob = b""
        for sm in STREAM_RE.finditer(body):
            candidate = sm.group(1)
            if b"/FlateDecode" in body:
                candidate = _inflate(candidate) or candidate
            blob = candidate
            break
        if not blob:
            continue
        object_id = f"{num} 0"
        digest = sha256_bytes(blob)
        embedded_entries.append(
            {"object_id": object_id, "filename": filename, "size": len(blob), "sha256": digest}
        )
        artifacts.append(
            ArtifactDraft(kind="embedded", data=blob, filename=filename, note="Archivo embebido en PDF")
        )
        findings.append(
            FindingDraft(
                category="embedded",
                description=f"Archivo embebido '{filename}' ({len(blob)} bytes, sha256 {digest[:16]}…)",
                suspicious=True,
                score=2.0,
                object_id=object_id,
                raw_ref=f"sha256:{digest}",
            )
        )

    if not objects:
        warnings.append("No se encontraron objetos; el PDF está dañado o usa xref streams no soportados")

    return ToolOutput(
        status="ok" if objects else "partial",
        findings=findings,
        artifacts=artifacts,
        warnings=warnings,
        data={
            "objects_total": len(objects),
            "streams_total": stream_count,
            "streams_decoded": decoded_count,
            "javascript": js_entries,
            "javascript_count": len(js_entries),
            "embedded_files": embedded_entries,
            "truncated": len(js_entries) >= MAX_JS_ARTIFACTS,
        },
        metrics={"objects": float(len(objects)), "streams": float(stream_count)},
    )
