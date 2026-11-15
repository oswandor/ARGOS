#!/usr/bin/env python
"""Smoke test de CrewAI + DeepSeek (sin herramientas): salida JSON validada.

Uso: python scripts/ping_crew.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from pydantic import BaseModel, Field  # noqa: E402

from core.settings import get_settings  # noqa: E402


class Verdict(BaseModel):
    verdict: str = Field(description="malicious | suspicious | benign | inconclusive")
    confidence: float = Field(ge=0, le=1)
    reason: str


def main() -> int:
    settings = get_settings()
    if not settings.deepseek_api_key:
        print("Falta DEEPSEEK_API_KEY en .env")
        return 2

    from crewai import LLM, Agent, Crew, Process, Task

    llm = LLM(
        model=f"deepseek/{settings.model_fast}",
        api_key=settings.deepseek_api_key,
        base_url=f"{settings.deepseek_base_url}/v1",
        temperature=0.0,
        max_tokens=2500,
    )
    agent = Agent(
        role="Triage de malware",
        goal="Clasificar metadatos de una muestra",
        backstory="Analista estático. Nunca inventa evidencia.",
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )
    task = Task(
        description=(
            "Un PDF tiene /OpenAction y /JavaScript. No hay más evidencia. "
            "Emite un veredicto preliminar. Responde SOLO con un objeto JSON con las claves "
            'verdict (string), confidence (número 0..1) y reason (string).'
        ),
        expected_output="Un objeto JSON con verdict, confidence y reason",
        agent=agent,
    )
    started = time.perf_counter()
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False)
    result = crew.kickoff()
    elapsed = int((time.perf_counter() - started) * 1000)

    raw = str(result).strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        raw = raw[raw.find("{") : raw.rfind("}") + 1]
    print("raw:", raw[:300])
    parsed = Verdict.model_validate_json(raw)
    print("validado:", parsed)
    metrics = getattr(crew, "usage_metrics", None)
    print("usage:", metrics)
    print(f"duracion: {elapsed} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
