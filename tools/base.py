"""Contratos de herramientas (sin MCP: funciones Python tipadas)."""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel


@dataclass
class ToolContext:
    sample_id: str
    filename: str
    detected_type: str
    data: bytes
    meta: dict = field(default_factory=dict)


class FindingDraft(BaseModel):
    category: str
    description: str
    suspicious: bool = False
    score: float = 0.0
    object_id: str | None = None
    raw_ref: str | None = None


@dataclass
class ArtifactDraft:
    kind: str
    data: bytes
    filename: str = ""
    note: str = ""


@dataclass
class ToolOutput:
    status: str = "ok"  # ok | partial | error | unavailable | timeout
    findings: list[FindingDraft] = field(default_factory=list)
    artifacts: list[ArtifactDraft] = field(default_factory=list)
    data: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)
    engines: dict[str, str] = field(default_factory=dict)
    sandbox: bool = False
    tool_id: str = ""
    tool_version: str = ""
    duration_ms: int = 0

    def summary(self) -> dict:
        """Vista compacta para el informe (sin bytes)."""
        return {
            "tool": self.tool_id,
            "version": self.tool_version,
            "status": self.status,
            "sandbox": self.sandbox,
            "warnings": self.warnings[:10],
            "metrics": {k: round(v, 3) for k, v in self.metrics.items()},
            "engines": self.engines,
            "data": self.data,
            "findings_count": len(self.findings),
            "artifacts_count": len(self.artifacts),
        }


@dataclass(frozen=True)
class DockerTool:
    """Ubicación de la herramienta dentro del sandbox."""

    image: str
    tool: str
    timeout_s: float = 120.0
