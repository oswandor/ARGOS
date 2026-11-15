"""Reputación local de IOCs (offline por defecto).

El MVP no contacta servicios externos: contrasta contra un seed local y contra
los IOCs ya vistos en la base de datos. Las consultas externas están detrás de
``ALLOW_EXTERNAL_INTEL`` y no se implementan todavía.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from core.sanitizer import defang
from core.settings import get_settings
from tools.base import FindingDraft, ToolContext, ToolOutput


@lru_cache
def _seed() -> dict[str, dict]:
    settings = get_settings()
    candidates = [
        settings.data_dir / "intel" / "seed.json",
        Path(__file__).resolve().parents[2] / "data" / "intel" / "seed.json",
    ]
    path = next((c for c in candidates if c.is_file()), None)
    if path is None:
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    index: dict[str, dict] = {}
    for item in raw.get("indicators", []):
        value = str(item.get("value", "")).strip().lower()
        if value:
            index[value] = item
    return index


def lookup(ctx: ToolContext) -> ToolOutput:
    iocs: list[dict] = ctx.meta.get("iocs", [])
    seed = _seed()
    results: list[dict] = []
    findings: list[FindingDraft] = []

    for ioc in iocs[:200]:
        value = str(ioc.get("value", ""))
        kind = str(ioc.get("type", ""))
        hit = seed.get(value.lower())
        verdict = str(hit.get("verdict", "unknown")) if hit else "unknown"
        results.append(
            {
                "type": kind,
                "value": value,
                "known": bool(hit),
                "verdict": verdict,
                "source": str(hit.get("source", "")) if hit else "local-seed",
            }
        )
        if hit and verdict in {"malicious", "suspicious"}:
            findings.append(
                FindingDraft(
                    category="intel",
                    description=f"IOC conocido ({kind}): {defang(value, kind)} → {verdict}",
                    suspicious=True,
                    score=3.0 if verdict == "malicious" else 1.5,
                    raw_ref=f"ioc:{value[:120]}",
                )
            )

    known = sum(1 for r in results if r["known"])
    return ToolOutput(
        findings=findings,
        data={
            "results": results,
            "known": known,
            "external_queries": False,
            "note": "Reputación local; no se contactaron servicios externos"
            if not get_settings().allow_external_intel
            else "Consultas externas habilitadas pero no implementadas en el MVP",
        },
        metrics={"iocs": float(len(results)), "known": float(known)},
    )
