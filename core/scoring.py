"""Agregación determinista de evidencia: riesgo, veredicto, ATT&CK y cadena.

El LLM nunca decide el veredicto: puede matizar la redacción, no los hechos.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MITRE_MAP: dict[str, tuple[str, str]] = {
    "pdf_action": ("T1204.002", "User Execution: Malicious File"),
    "action": ("T1204.002", "User Execution: Malicious File"),
    "javascript": ("T1059.007", "Command and Scripting Interpreter: JavaScript"),
    "execution": ("T1059.005", "Command and Scripting Interpreter: Visual Basic"),
    "macro": ("T1204.002", "User Execution: Malicious File"),
    "autoexec": ("T1204.002", "User Execution: Malicious File"),
    "macro_api": ("T1059.005", "Command and Scripting Interpreter: Visual Basic"),
    "downloader": ("T1105", "Ingress Tool Transfer"),
    "obfuscation": ("T1027", "Obfuscated Files or Information"),
    "embedded": ("T1027", "Obfuscated Files or Information"),
    "ioc": ("T1071.001", "Application Layer Protocol: Web Protocols"),
    "architecture": ("T1055", "Process Injection"),
    "syscall": ("T1106", "Native API"),
}

CHAIN_ORDER = [
    "extension_mismatch",
    "pdf_action",
    "action",
    "javascript",
    "obfuscation",
    "execution",
    "downloader",
    "embedded",
    "macro",
    "autoexec",
    "macro_api",
    "architecture",
    "syscall",
    "ioc",
]

CHAIN_TEXT = {
    "extension_mismatch": "El archivo no coincide con su extensión declarada",
    "pdf_action": "El documento contiene una acción automática al abrirse",
    "action": "El documento define acciones automáticas",
    "macro": "El documento incluye un proyecto de macros VBA",
    "autoexec": "Una macro se ejecuta automáticamente al abrir el documento",
    "macro_api": "Las macros invocan APIs de ejecución o descarga",
    "javascript": "Hay código JavaScript incrustado en el documento",
    "obfuscation": "El código está ofuscado o empaquetado",
    "execution": "El script usa interfaces para lanzar procesos",
    "downloader": "El script puede descargar y escribir archivos",
    "embedded": "El documento contiene archivos embebidos",
    "architecture": "Se identificó código compatible con shellcode",
    "syscall": "El shellcode invoca llamadas al sistema",
    "ioc": "Se extrajeron indicadores de compromiso",
}

CONTENT_TOOLS = {"pdfid", "pdf_parser", "js_analyzer", "office_scan", "shellcode"}


@dataclass
class Assessment:
    risk_score: float
    verdict: str
    confidence: float
    mitre: list[dict] = field(default_factory=list)
    attack_chain: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def aggregate(
    findings: list[dict],
    coverage: dict[str, list[str]],
    detected_type: str,
    warnings: list[str],
) -> Assessment:
    per_category: dict[str, float] = {}
    for finding in findings:
        if not finding.get("suspicious"):
            continue
        category = finding.get("category", "other")
        per_category[category] = max(per_category.get(category, 0.0), float(finding.get("score", 0.0)))

    risk = sum(per_category.values())
    if "javascript" in per_category and per_category.keys() & {"pdf_action", "action", "autoexec"}:
        risk += 1.0
    if "execution" in per_category and "downloader" in per_category:
        risk += 1.0
    risk = round(min(risk, 10.0), 2)

    executed = coverage.get("executed", [])
    content_ok = [t for t in executed if t in CONTENT_TOOLS]
    supported = detected_type in {"pdf", "office", "javascript", "shellcode", "pe"}

    if not supported or not content_ok:
        verdict = "inconclusive"
        confidence = 0.3
    elif risk >= 6.5:
        verdict = "malicious"
        confidence = 0.85
    elif risk >= 2.0:
        verdict = "suspicious"
        confidence = 0.65
    else:
        verdict = "benign"
        confidence = 0.6

    confidence += min(0.08 * len(content_ok), 0.16)
    confidence -= min(0.04 * len(warnings), 0.12)
    if coverage.get("unavailable") or coverage.get("skipped"):
        confidence -= 0.03
    confidence = round(max(0.3, min(confidence, 0.95)), 2)

    mitre: list[dict] = []
    seen: set[str] = set()
    for category in per_category:
        entry = MITRE_MAP.get(category)
        if entry and entry[0] not in seen:
            seen.add(entry[0])
            mitre.append({"technique": entry[0], "name": entry[1]})

    chain = [
        {"step": i + 1, "category": cat, "description": CHAIN_TEXT[cat]}
        for i, cat in enumerate(c for c in CHAIN_ORDER if c in per_category)
    ]

    limitations = [
        "Análisis exclusivamente estático: el comportamiento real de la muestra no fue observado.",
        "El veredicto se basa en heurísticas y patrones; puede haber falsos positivos y negativos.",
    ]
    if coverage.get("unavailable"):
        limitations.append("Motores no ejecutados: " + ", ".join(coverage["unavailable"]))
    if coverage.get("skipped"):
        limitations.append("Análisis omitidos por política: " + ", ".join(coverage["skipped"]))
    if detected_type not in {"pdf", "office", "javascript", "shellcode"}:
        limitations.append(f"Tipo '{detected_type}' sin analizador dedicado en el MVP.")
    limitations.extend(warnings[:8])

    return Assessment(
        risk_score=risk,
        verdict=verdict,
        confidence=confidence,
        mitre=mitre,
        attack_chain=chain,
        limitations=limitations,
    )
