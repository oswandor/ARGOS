"""Herramientas expuestas a los agentes CrewAI.

Reglas:
- El agente nunca recibe shell, Docker ni red. Solo puede pedir herramientas del
  registro, y el backend vuelve a validar allowlist, presupuesto y tipo.
- Cada llamada devuelve JSON compacto; el agente decide, el backend ejecuta.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable

from pydantic import BaseModel, Field, PrivateAttr

try:  # CrewAI es opcional: el pipeline determinista no depende de él.
    from crewai.tools import BaseTool
except ImportError:  # pragma: no cover - entorno sin crewai
    BaseTool = object  # type: ignore[assignment,misc]


class CapabilitiesInput(BaseModel):
    file_type: str = Field(description="Tipo detectado: pdf | office | javascript | shellcode")


class RunAnalysisInput(BaseModel):
    tool_id: str = Field(description="Herramienta a ejecutar, p. ej. pdfid, pdf_parser, js_analyzer")
    reason: str = Field(default="", description="Por qué se necesita esta evidencia")


class CapabilitiesTool(BaseTool):  # type: ignore[misc]
    name: str = "analysis_capabilities"
    description: str = (
        "Devuelve las herramientas permitidas para un tipo de archivo y su disponibilidad "
        "real (incluye si corren en el sandbox Docker). Úsala antes de pedir análisis."
    )
    args_schema: type[BaseModel] = CapabilitiesInput
    capabilities: Callable[[str], dict] = Field(exclude=True)

    def _run(self, file_type: str) -> str:
        try:
            return json.dumps(self.capabilities(file_type), ensure_ascii=False)
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"{type(exc).__name__}: {exc}"})


class RunAnalysisTool(BaseTool):  # type: ignore[misc]
    name: str = "run_analysis"
    description: str = (
        "Ejecuta una herramienta de análisis permitida sobre la muestra actual y devuelve "
        "el resumen de evidencia (hallazgos, IOCs, estado). No acepta comandos ni rutas."
    )
    args_schema: type[BaseModel] = RunAnalysisInput
    runner: Callable[[str], dict] = Field(exclude=True)
    max_calls: int = 4
    calls: int = 0
    _call_lock: threading.Lock = PrivateAttr(default_factory=threading.Lock)

    def _run(self, tool_id: str, reason: str = "") -> str:
        with self._call_lock:
            if self.calls >= self.max_calls:
                return json.dumps(
                    {
                        "status": "rejected",
                        "error": f"presupuesto de herramientas agotado ({self.max_calls})",
                    }
                )
            self.calls += 1
        try:
            result = self.runner(tool_id)
        except Exception as exc:  # noqa: BLE001
            result = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
        result["reason"] = reason[:200]
        return json.dumps(result, ensure_ascii=False)
