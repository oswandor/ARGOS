"""Contratos de salida de los agentes CrewAI.

El LLM nunca devuelve texto libre al pipeline: cada tarea produce un objeto
validado con Pydantic. Si no valida, se descarta y se cae al camino determinista.
"""

from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["malicious", "suspicious", "benign", "inconclusive"]


class AnalysisPlan(BaseModel):
    route: str = Field(description="pdf | office | javascript | shellcode | unsupported")
    tools_used: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    rationale: str = ""


class FamilyFinding(BaseModel):
    family: str
    observations: list[str] = Field(default_factory=list)
    concerns: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0, le=1)


class ValidationDecision(BaseModel):
    consistent: bool = True
    contradictions: list[str] = Field(default_factory=list)
    unsupported_claims: list[str] = Field(default_factory=list)
    notes: str = ""


class ReportNarrative(BaseModel):
    summary: str
    attack_chain: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    confidence_adjustment: float = Field(default=0.0, ge=-0.05, le=0.05)


def parse_model(raw: str, model: type[BaseModel]) -> BaseModel | None:
    """Busca el primer objeto JSON que valide contra el modelo. Nunca lanza.

    Tolera bloques markdown, texto alrededor y varios objetos: recorre cada ``{``
    y usa ``raw_decode`` en lugar de confiar en el primer/último del texto.
    """
    if not raw:
        return None
    text = raw.replace("```json", "```").replace("```", "")
    # Tolerar comas finales típicas de los LLM antes de intentar el parseo.
    text = re.sub(r",\s*([}\]])", r"\1", text)
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            candidate, _end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if not isinstance(candidate, dict):
            continue
        try:
            return model.model_validate(candidate)
        except (ValueError, TypeError):
            continue
    return None
