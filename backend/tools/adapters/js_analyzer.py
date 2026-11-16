"""Analizador estático de JavaScript/VBScript (sin ejecución).

Incluye desempaquetado del packer de Dean Edwards, decodificación de escapes y
``String.fromCharCode``, extracción de IOCs y APIs peligrosas. box-js queda como
paso posterior (requiere Node y aislamiento reforzado).
"""

from __future__ import annotations

import base64
import binascii
import re

from core.hashing import entropy
from tools.base import FindingDraft, ToolContext, ToolOutput

URL_RE = re.compile(r"""(?i)\b(?:https?|ftp)://[^\s"'<>\)\]\}]+""")
DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|su|top|xyz|info|biz|onion|tk|ml|ga|cf|gq|zip|mov|site|online)\b"
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
EXEC_RE = re.compile(
    r"(?i)\b[\w\-. ]{1,64}\.(?:exe|dll|ps1|vbs|vbe|bat|cmd|scr|js|jse|hta|jar|msi)\b"
)

SUSPICIOUS_TOKENS: dict[str, tuple[float, str]] = {
    "WScript.Shell": (3.0, "ejecución"),
    "Shell.Application": (2.5, "ejecución"),
    "ShellExecute": (2.5, "ejecución"),
    "Win32_Process": (2.5, "ejecución"),
    "cmd.exe": (2.0, "ejecución"),
    "powershell": (2.0, "ejecución"),
    "ADODB.Stream": (2.5, "escritura de archivos"),
    "SaveToFile": (2.0, "escritura de archivos"),
    "MSXML2.XMLHTTP": (2.5, "descarga"),
    "XMLHTTP": (1.5, "descarga"),
    "ActiveXObject": (2.0, "ActiveX"),
    "CreateObject": (1.5, "creación de objetos COM"),
    "GetObject": (1.0, "COM"),
    "eval": (1.2, "evaluación dinámica"),
    "unescape": (1.0, "ofuscación"),
    "String.fromCharCode": (1.5, "ofuscación"),
    "document.write": (1.0, "inyección DOM"),
    "atob": (1.0, "codificación"),
    "base64": (1.0, "codificación"),
    "WScript": (1.5, "host Windows Script"),
}

PACKER_RE = re.compile(
    r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)"
    r"\s*\{.*?\}\s*\(\s*'((?:[^'\\]|\\.)*)'\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*"
    r"'((?:[^'\\]|\\.)*)'\s*\.split\s*\(\s*['\"]\|['\"]\s*\)",
    re.S,
)

MAX_DEOBFUSCATED = 400_000


def _decode_js_escapes(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        body = match.group(1)
        if body.startswith("x"):
            return chr(int(body[1:], 16))
        if body.startswith("u"):
            return chr(int(body[1:], 16))
        return chr(int(body, 8))

    text = re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r"\\u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r"\\([0-7]{1,3})", repl, text)
    return text


def _digit(num: int, base: int) -> str:
    if num > 35:
        return chr(num + 29)
    return "0123456789abcdefghijklmnopqrstuvwxyz"[num]


def _to_base(num: int, base: int) -> str:
    if num < base:
        return _digit(num, base)
    return _to_base(num // base, base) + _digit(num % base, base)


def _unpack_packer(text: str) -> str | None:
    match = PACKER_RE.search(text)
    if not match:
        return None
    payload = _decode_js_escapes(match.group(1))
    base = int(match.group(2) or 62)
    count = int(match.group(3) or 0)
    words = _decode_js_escapes(match.group(4)).split("|")
    if not count or base < 2:
        return None
    out = payload
    try:
        for index in range(count - 1, -1, -1):
            if index < len(words) and words[index]:
                token = re.escape(_to_base(index, base))
                out = re.sub(r"(?<![0-9A-Za-z])" + token + r"(?![0-9A-Za-z])", words[index], out)
    except (ValueError, IndexError):
        return None
    return out if out != payload and len(out) < MAX_DEOBFUSCATED else None


def _from_charcode(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        try:
            codes = [int(x) for x in re.findall(r"\d+", match.group(1))]
        except ValueError:
            return match.group(0)
        chars = "".join(chr(c) for c in codes if 1 <= c <= 0x10FFFF)
        return chars if len(chars) >= 3 else match.group(0)

    return re.sub(r"String\.fromCharCode\(\s*([\d,\s]{3,})\)", repl, text)


def _base64_strings(text: str) -> list[str]:
    out: list[str] = []
    for match in re.finditer(r"['\"]([A-Za-z0-9+/]{32,}={0,2})['\"]", text):
        blob = match.group(1)
        try:
            decoded = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
        if decoded and printable / len(decoded) > 0.85:
            out.append(decoded.decode("latin-1"))
    return out


def _percent_unescape(text: str) -> str:
    """Decodifica cadenas tipo ``unescape('%68%74%74%70...')``."""

    def repl(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    if "unescape(" not in text.lower():
        return text
    return re.sub(r"%([0-9A-Fa-f]{2})", repl, text)


def deobfuscate(text: str) -> tuple[str, list[str]]:
    steps: list[str] = []
    current = text
    unpacked = _unpack_packer(current)
    if unpacked:
        current = unpacked
        steps.append("packer_dean_edwards")
    decoded = _decode_js_escapes(current)
    if decoded != current:
        current = decoded
        steps.append("escapes")
    charcode = _from_charcode(current)
    if charcode != current:
        current = charcode
        steps.append("fromCharCode")
    percent = _percent_unescape(current)
    if percent != current:
        current = percent
        steps.append("percent_unescape")
    for blob in _base64_strings(current)[:5]:
        if blob not in current:
            current += "\n/* base64 */\n" + blob
            steps.append("base64")
    return current, steps


def _valid_ipv4(candidate: str) -> bool:
    parts = candidate.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def extract_iocs(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        key = (kind, value.lower())
        if key not in seen and len(value) <= 500:
            seen.add(key)
            found.append((kind, value))

    for match in URL_RE.findall(text):
        add("url", match.rstrip(".,;"))
    for match in IPV4_RE.findall(text):
        if _valid_ipv4(match):
            add("ip", match)
    for match in EMAIL_RE.findall(text):
        add("email", match)
    for match in DOMAIN_RE.findall(text):
        if not any(match.lower() in url.lower() for _, url in found if url):
            add("domain", match)
    return found[:100]


def analyze(ctx: ToolContext) -> ToolOutput:
    raw = ctx.data
    limit = ctx.meta.get("max_js_bytes", 200_000)
    truncated = len(raw) > limit
    text = raw[:limit].decode("latin-1", errors="replace")

    deobfuscated, steps = deobfuscate(text)
    iocs = extract_iocs(text + "\n" + deobfuscated)

    tokens = {token: len(re.findall(re.escape(token), text, re.I)) for token in SUSPICIOUS_TOKENS}
    tokens = {k: v for k, v in tokens.items() if v}

    findings: list[FindingDraft] = []
    if any(k in tokens for k in ("WScript.Shell", "Shell.Application", "Win32_Process", "cmd.exe", "powershell")):
        findings.append(
            FindingDraft(
                category="execution",
                description="El script usa APIs de ejecución de procesos/COM: "
                + ", ".join(sorted({SUSPICIOUS_TOKENS[k][1] for k in tokens if k in SUSPICIOUS_TOKENS})),
                suspicious=True,
                score=3.5,
            )
        )
    if any(k in tokens for k in ("ADODB.Stream", "SaveToFile", "MSXML2.XMLHTTP", "XMLHTTP")):
        findings.append(
            FindingDraft(
                category="downloader",
                description="El script descarga y/o escribe archivos (patrón descargador)",
                suspicious=True,
                score=3.0,
            )
        )
    if any(k in tokens for k in ("eval", "unescape", "String.fromCharCode", "atob", "base64")) or steps:
        findings.append(
            FindingDraft(
                category="obfuscation",
                description="Ofuscación detectada: " + (", ".join(steps) if steps else "uso de eval/unescape"),
                suspicious=True,
                score=2.0,
            )
        )
    if iocs:
        urls = sum(1 for kind, _ in iocs if kind == "url")
        domains = sum(1 for kind, _ in iocs if kind == "domain")
        ips = sum(1 for kind, _ in iocs if kind == "ip")
        findings.append(
            FindingDraft(
                category="ioc",
                description=f"{len(iocs)} indicadores extraídos "
                f"({urls} URLs, {domains} dominios, {ips} IPs)",
                suspicious=True,
                score=1.5 + min(urls, 3) * 0.5,
            )
        )

    warnings: list[str] = []
    if truncated:
        warnings.append(f"Script truncado a {limit} bytes para análisis")
    if steps:
        warnings.append("Código desempaquetado; el análisis se hizo sobre la versión decodificada")

    preview = deobfuscated[:600] if steps else text[:600]
    return ToolOutput(
        findings=findings,
        warnings=warnings,
        data={
            "length": len(raw),
            "truncated": truncated,
            "entropy": round(entropy(raw[:limit]), 3),
            "deobfuscation_steps": steps,
            "suspicious_tokens": tokens,
            "iocs": [{"type": kind, "value": value} for kind, value in iocs],
            "ioc_count": len(iocs),
            "referenced_files": sorted(set(EXEC_RE.findall(text + "\n" + deobfuscated)))[:20],
            "preview": preview,
            "confidence_note": "Análisis estático; no se ejecutó el script",
        },
        metrics={"bytes": float(len(raw)), "iocs": float(len(iocs))},
    )
