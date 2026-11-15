"""Registro de todas las herramientas del MVP (una sola vez por proceso)."""

from __future__ import annotations

from core.settings import get_settings
from tools import registry
from tools.adapters import intel, js_analyzer, office, pdf_parser, pdfid, shellcode, triage, yara_scan
from tools.base import DockerTool, ToolContext, ToolOutput

_DONE = False


def _image(family: str) -> str:
    settings = get_settings()
    return f"{settings.worker_image_prefix}-{family}:{settings.worker_image_tag}"


def register_all() -> None:
    global _DONE
    if _DONE:
        return
    specs = [
        (
            registry.ToolSpec(
                id="triage",
                name="Triage determinista",
                version="1.0",
                formats=("any",),
                description="Firma real, hashes, entropía y coherencia de extensión",
            ),
            triage.triage,
        ),
        (
            registry.ToolSpec(
                id="yara",
                name="YARA (reglas ARGOS)",
                version="1.0",
                formats=("pdf", "office", "javascript", "shellcode"),
                description="Firmas propias para PDF, Office, JS y shellcode",
                requires=("yara",),
                docker=DockerTool(image=_image("yara"), tool="yara", timeout_s=60),
            ),
            yara_scan.scan,
        ),
        (
            registry.ToolSpec(
                id="pdfid",
                name="PDFiD (Didier Stevens + nativo)",
                version="1.1",
                formats=("pdf",),
                description="Conteo de tokens peligrosos (/JS, /OpenAction, /Launch…)",
                docker=DockerTool(image=_image("pdf"), tool="pdfid", timeout_s=90),
            ),
            pdfid.scan,
        ),
        (
            registry.ToolSpec(
                id="pdf_parser",
                name="pdf-parser (Didier Stevens + nativo)",
                version="1.1",
                formats=("pdf",),
                description="Objetos, streams FlateDecode, JavaScript y archivos embebidos",
                docker=DockerTool(image=_image("pdf"), tool="pdf_parser", timeout_s=120),
            ),
            pdf_parser.parse,
        ),
        (
            registry.ToolSpec(
                id="js_analyzer",
                name="JavaScript (box-js + estático)",
                version="1.1",
                formats=("javascript",),
                description="Emulación box-js, desempaquetado, IOCs y APIs peligrosas",
                docker=DockerTool(image=_image("js"), tool="js", timeout_s=150),
            ),
            js_analyzer.analyze,
        ),
        (
            registry.ToolSpec(
                id="office_scan",
                name="Office (oletools + nativo)",
                version="1.1",
                formats=("office",),
                description="olevba/oleobj/mraptor: macros VBA, autoexec y objetos embebidos",
                requires=("olefile",),
                docker=DockerTool(image=_image("office"), tool="office", timeout_s=120),
            ),
            office.scan,
        ),
        (
            registry.ToolSpec(
                id="shellcode",
                name="Shellcode (Capstone + LIEF + binutils)",
                version="1.1",
                formats=("shellcode", "pe"),
                description="Arquitectura, desensamblado, secciones y cadenas",
                requires=("capstone",),
                docker=DockerTool(image=_image("binary"), tool="binary", timeout_s=120),
            ),
            shellcode.scan,
        ),
        (
            registry.ToolSpec(
                id="intel",
                name="Reputación local",
                version="1.0",
                formats=("any",),
                description="Contraste de IOCs contra seed local, sin consultas externas",
            ),
            intel.lookup,
        ),
    ]
    for spec, fn in specs:
        registry.register(spec, fn)
    _DONE = True


__all__ = ["register_all", "ToolOutput", "ToolContext"]
