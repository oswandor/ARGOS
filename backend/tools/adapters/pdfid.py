"""PDFiD nativo: clasificación de tokens sospechosos sin dependencias externas.

Equivalente funcional (subconjunto) de pdfid.py de Didier Stevens. Trabaja sobre
bytes y tolera PDFs malformados.
"""

from __future__ import annotations

import re

from tools.base import FindingDraft, ToolContext, ToolOutput

TOKENS: dict[str, re.Pattern[bytes]] = {
    "/JavaScript": re.compile(rb"/JavaScript\b"),
    "/JS": re.compile(rb"/JS(?![A-Za-z])"),
    "/OpenAction": re.compile(rb"/OpenAction\b"),
    "/AA": re.compile(rb"/AA(?![A-Za-z])"),
    "/Launch": re.compile(rb"/Launch\b"),
    "/EmbeddedFile": re.compile(rb"/EmbeddedFile\b"),
    "/AcroForm": re.compile(rb"/AcroForm\b"),
    "/XFA": re.compile(rb"/XFA\b"),
    "/RichMedia": re.compile(rb"/RichMedia\b"),
    "/JBIG2Decode": re.compile(rb"/JBIG2Decode\b"),
    "/ObjStm": re.compile(rb"/ObjStm\b"),
    "/URI": re.compile(rb"/URI\b"),
    "/SubmitForm": re.compile(rb"/SubmitForm\b"),
    "/GoToE": re.compile(rb"/GoToE\b"),
    "/GoToR": re.compile(rb"/GoToR\b"),
    "/Encrypt": re.compile(rb"/Encrypt\b"),
}

# (token, peso, categoría, descripción)
RULES: list[tuple[str, float, str, str]] = [
    ("/Launch", 4.0, "action", "Acción /Launch: puede lanzar un programa externo"),
    ("/JavaScript", 2.0, "javascript", "Presencia de JavaScript en el documento"),
    ("/JS", 1.0, "javascript", "Entrada /JS (código JavaScript)"),
    ("/AA", 3.0, "action", "Acciones adicionales automáticas (/AA)"),
    ("/OpenAction", 1.5, "action", "Acción automática al abrir (/OpenAction)"),
    ("/EmbeddedFile", 2.0, "embedded", "Archivo embebido en el PDF"),
    ("/RichMedia", 2.0, "action", "Contenido RichMedia (Flash/JS)"),
    ("/XFA", 2.0, "action", "Formulario XFA: lógica incrustada"),
    ("/JBIG2Decode", 2.0, "exploit", "Filtro JBIG2 (histórico de vulnerabilidades)"),
    ("/SubmitForm", 1.0, "exfiltration", "Envío automático de datos de formulario"),
    ("/GoToE", 1.5, "action", "Acción hacia archivo embebido"),
]


def scan(ctx: ToolContext) -> ToolOutput:
    data = ctx.data
    counts = {token: len(pattern.findall(data)) for token, pattern in TOKENS.items()}

    version = "desconocida"
    header = re.search(rb"%PDF-(\d\.\d)", data[:1024])
    if header:
        version = header.group(1).decode()

    objects = len(re.findall(rb"\b\d+\s+\d+\s+obj\b", data))
    eofs = len(re.findall(rb"%%EOF", data))

    findings: list[FindingDraft] = []
    total_js = counts["/JavaScript"] + counts["/JS"]
    warnings: list[str] = []

    for token, weight, category, description in RULES:
        n = counts[token]
        if not n:
            continue
        score = weight
        if token in {"/JavaScript", "/JS"} and n > 1:
            score += 0.5 * min(n - 1, 4)
        if token == "/OpenAction" and total_js:
            score += 2.0
            description += " junto a JavaScript (cadena de ejecución típica)"
        findings.append(
            FindingDraft(
                category=category,
                description=f"{description}. Ocurrencias: {n}",
                suspicious=token != "/ObjStm",
                score=round(score, 2),
            )
        )

    if counts["/Encrypt"]:
        warnings.append("PDF cifrado: los streams pueden no ser inspeccionables")
    if objects == 0:
        warnings.append("No se localizaron objetos con 'N 0 obj'; PDF posiblemente dañado")

    return ToolOutput(
        findings=findings,
        warnings=warnings,
        data={
            "pdf_version": version,
            "tokens": {k: v for k, v in counts.items() if v},
            "objects": objects,
            "eof_markers": eofs,
            "incremental_updates": max(0, eofs - 1),
            "javascript_total": total_js,
            "has_openaction": counts["/OpenAction"] > 0,
            "has_embedded": counts["/EmbeddedFile"] > 0,
        },
    )
