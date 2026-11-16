"""Política de herramientas y presupuesto por investigación.

Ninguna herramienta se ejecuta si no está en la allowlist del tipo de muestra.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic

# tipo detectado -> herramientas permitidas
ALLOWLIST: dict[str, tuple[str, ...]] = {
    "pdf": ("triage", "yara", "pdfid", "pdf_parser", "intel"),
    "office": ("triage", "yara", "office_scan", "intel"),
    "javascript": ("triage", "yara", "js_analyzer", "intel"),
    "shellcode": ("triage", "yara", "shellcode", "intel"),
    "pe": ("triage", "yara", "shellcode", "intel"),
    "unknown": ("triage", "yara", "intel"),
}

# herramientas que pueden analizar artefactos hijos
CHILD_ALLOWLIST: dict[str, tuple[str, ...]] = {
    "pdf": ("pdfid", "pdf_parser", "yara"),
    "javascript": ("js_analyzer", "yara"),
    "office": ("office_scan", "yara"),
    "shellcode": ("shellcode", "yara"),
    "unknown": ("yara",),
}


class PolicyError(RuntimeError):
    pass


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class Budget:
    max_tool_calls: int = 60
    max_seconds: float = 900.0
    max_children: int = 20
    max_depth: int = 3
    tool_calls: int = 0
    children: int = 0
    started: float = field(default_factory=monotonic)

    def spend_tool_call(self, tool_id: str) -> None:
        if self.tool_calls >= self.max_tool_calls:
            raise BudgetExceeded(f"presupuesto de herramientas agotado antes de {tool_id}")
        self.tool_calls += 1

    def spend_child(self) -> None:
        if self.children >= self.max_children:
            raise BudgetExceeded("límite de artefactos hijos alcanzado")
        self.children += 1

    @property
    def elapsed_s(self) -> float:
        return monotonic() - self.started

    def check_time(self) -> None:
        if self.elapsed_s > self.max_seconds:
            raise BudgetExceeded(f"tiempo máximo de investigación excedido ({self.max_seconds:.0f}s)")


def authorize(tool_id: str, detected_type: str, *, is_child: bool = False) -> None:
    table = CHILD_ALLOWLIST if is_child else ALLOWLIST
    allowed = table.get(detected_type, table["unknown"])
    if tool_id not in allowed:
        raise PolicyError(
            f"herramienta '{tool_id}' no permitida para tipo '{detected_type}'"
            f" (permitidas: {', '.join(allowed)})"
        )
