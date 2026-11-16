"""Sanitización de evidencia antes de cualquier salida externa (LLM, logs, API).

Regla dura: nunca sale un byte de la muestra, una ruta local, un correo, una
credencial ni una URL viva.
"""

from __future__ import annotations

import re
from typing import Any

URL_RE = re.compile(r"(?i)\b(https?|ftp)://[^\s\"'<>\)\]]+")
DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|su|top|xyz|info|biz|onion|tk|ml|ga|cf|gq|zip|mov)\b"
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
WIN_PATH_RE = re.compile(r"(?i)\b[a-z]:\\(?:[^\\\s\"'<>|]+\\)*[^\\\s\"'<>|]*")
UNIX_PATH_RE = re.compile(r"(?<![\w.])/(?:home|users|root|tmp|var|etc)/[^\s\"'<>|]+")
SECRET_RES = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\b(api[_-]?key|token|password|passwd|secret)\s*[:=]\s*[\"']?[^\s\"',;]{6,}"),
]


def defang_url(url: str) -> str:
    out = url.replace("https://", "hxxps://").replace("http://", "hxxp://").replace("ftp://", "fxp://")
    return out.replace(".", "[.]")


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


def defang(value: str, ioc_type: str) -> str:
    if ioc_type == "url":
        return defang_url(value)
    if ioc_type == "domain":
        return defang_domain(value)
    if ioc_type == "ip":
        return defang_ip(value)
    return value


def redact_text(text: str) -> str:
    """Elimina rutas, correos y credenciales de un texto libre."""
    text = EMAIL_RE.sub("[email-redactado]", text)
    text = WIN_PATH_RE.sub("[ruta-redactada]", text)
    text = UNIX_PATH_RE.sub("[ruta-redactada]", text)
    for pattern in SECRET_RES:
        text = pattern.sub("[secreto-redactado]", text)
    return text


def truncate(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[... {len(text) - limit} caracteres omitidos ...]"


def sanitize_text(text: str, *, defang_iocs: bool = True, limit: int = 4000) -> str:
    out = redact_text(text)
    if defang_iocs:
        out = URL_RE.sub(lambda m: defang_url(m.group(0)), out)
        out = IPV4_RE.sub(lambda m: defang_ip(m.group(0)), out)
        out = DOMAIN_RE.sub(lambda m: defang_domain(m.group(0)), out)
    return truncate(out, limit)


def sanitize_bundle(value: Any, *, limit: int = 2000, depth: int = 0) -> Any:
    """Copia profunda sanitizada para enviar al LLM (nunca bytes)."""
    if depth > 8:
        return "[...]"
    if isinstance(value, bytes):
        return "[bytes omitidos]"
    if isinstance(value, str):
        return sanitize_text(value, limit=limit)
    if isinstance(value, dict):
        return {str(k): sanitize_bundle(v, limit=limit, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_bundle(v, limit=limit, depth=depth + 1) for v in value[:200]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:200]
