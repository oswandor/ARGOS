"""Construcción del informe (JSON estable, Markdown y HTML)."""

from __future__ import annotations

import html
from datetime import UTC, datetime
from typing import Any

SCHEMA = "argos.report/1"


def _fmt_iocs(iocs: list[dict]) -> list[dict]:
    return [
        {
            "type": i.get("type", ""),
            "value": i.get("defanged", ""),
            "verdict": i.get("verdict", "unknown"),
            "known": bool(i.get("known")),
        }
        for i in iocs
    ]


def build_report(
    *,
    investigation_id: str,
    sample: dict,
    children: list[dict],
    assessment: Any,
    evidence: list[dict],
    tool_outputs: list[dict],
    iocs: list[dict],
    coverage: dict[str, list[str]],
    llm_meta: dict,
    llm_review: dict | None,
    timings: dict[str, int],
    crew_meta: dict | None = None,
) -> dict:
    summary = (llm_review or {}).get("summary") or _fallback_summary(assessment, sample)
    chain = [step["description"] for step in assessment.attack_chain]
    if llm_review and llm_review.get("attack_chain"):
        chain = llm_review["attack_chain"]
    recommendations = (llm_review or {}).get("recommendations") or _fallback_recommendations(assessment)

    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "investigation_id": investigation_id,
        "sample": sample,
        "children": children,
        "verdict": assessment.verdict,
        "confidence": assessment.confidence,
        "risk_score": assessment.risk_score,
        "summary": summary,
        "attack_chain": chain,
        "findings": evidence,
        "iocs": _fmt_iocs(iocs),
        "mitre": assessment.mitre,
        "coverage": coverage,
        "limitations": assessment.limitations,
        "recommendations": recommendations,
        "tools": tool_outputs,
        "timings_ms": timings,
        "llm": llm_meta,
        "crew": crew_meta or {"status": "disabled"},
    }


def _fallback_summary(assessment: Any, sample: dict) -> str:
    name = sample.get("filename") or sample.get("sha256", "")[:16]
    verdict_text = {
        "malicious": "El archivo presenta comportamiento malicioso según la evidencia estática recogida",
        "suspicious": "El archivo presenta características sospechosas que requieren revisión",
        "benign": "No se encontraron indicadores sospechosos en el análisis realizado",
        "inconclusive": "La evidencia disponible no permite emitir una conclusión",
    }[assessment.verdict]
    categories = ", ".join(step["category"] for step in assessment.attack_chain[:6]) or "sin hallazgos"
    return (
        f"{verdict_text}. Archivo: {name}. "
        f"Puntuación de riesgo {assessment.risk_score}/10 (confianza {assessment.confidence}). "
        f"Hallazgos relevantes: {categories}. "
        "El análisis fue estático: no se ejecutó la muestra."
    )


def _fallback_recommendations(assessment: Any) -> list[str]:
    if assessment.verdict in {"malicious", "suspicious"}:
        return [
            "No abrir el archivo fuera de un entorno aislado.",
            "Bloquear los IOCs listados en las herramientas perimetrales.",
            "Solicitar detonación en sandbox antes de descartar el caso.",
            "Revisar si el archivo llegó por correo y aplicar cuarentena al remitente.",
        ]
    if assessment.verdict == "inconclusive":
        return [
            "Revisar manualmente el archivo o ampliar la cobertura de herramientas.",
            "No clasificar el archivo como limpio solo por ausencia de alertas.",
        ]
    return ["Archivar el caso y conservar el hash para correlación futura."]


def to_markdown(report: dict) -> str:
    s = report["sample"]
    lines = [
        f"# Informe ARGOS — {s.get('filename') or s.get('sha256', '')[:16]}",
        "",
        f"**Veredicto:** `{report['verdict']}` · **Confianza:** {report['confidence']} · "
        f"**Riesgo:** {report['risk_score']}/10",
        "",
        "| Campo | Valor |",
        "| --- | --- |",
        f"| SHA-256 | `{s.get('sha256')}` |",
        f"| Tipo detectado | {s.get('detected_type')} |",
        f"| Tamaño | {s.get('size')} bytes |",
        f"| MIME | {s.get('mime')} |",
        f"| Investigación | `{report['investigation_id']}` |",
        "",
        "## Resumen",
        "",
        report["summary"],
        "",
        "## Cadena de ataque (inferida)",
        "",
    ]
    lines += [f"{i + 1}. {step}" for i, step in enumerate(report["attack_chain"])] or ["Sin cadena inferida."]
    lines += [
        "",
        "## Hallazgos",
        "",
        "| Evidencia | Herramienta | Categoría | Descripción | Score |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in report["findings"]:
        desc = str(f.get("description", "")).replace("|", "\\|")[:160]
        lines.append(
            f"| `{f.get('evidence_id')}` | {f.get('tool')} | {f.get('category')} | {desc} | {f.get('score')} |"
        )
    lines += ["", "## IOCs", ""]
    if report["iocs"]:
        lines += ["| Tipo | Valor (defanged) | Veredicto |", "| --- | --- | --- |"]
        lines += [f"| {i['type']} | `{i['value']}` | {i['verdict']} |" for i in report["iocs"]]
    else:
        lines.append("No se extrajeron indicadores.")
    lines += ["", "## MITRE ATT&CK", ""]
    lines += [f"- **{m['technique']}** — {m['name']}" for m in report["mitre"]] or ["Sin técnicas mapeadas."]
    lines += ["", "## Cobertura del análisis", ""]
    for key, label in (("executed", "Ejecutadas"), ("unavailable", "No disponibles"), ("skipped", "Omitidas")):
        value = ", ".join(report["coverage"].get(key, [])) or "—"
        lines.append(f"- **{label}:** {value}")
    crew = report.get("crew") or {}
    if crew.get("status") not in (None, "disabled"):
        lines += ["", "## Agentes (CrewAI)", ""]
        lines.append(f"- **Estado:** {crew.get('status')}")
        lines.append(f"- **Agentes:** {', '.join(crew.get('agents') or []) or '—'}")
        lines.append(
            f"- **Tokens:** {crew.get('tokens', 0)} · **Duración:** {crew.get('duration_ms', 0)} ms"
        )
        if crew.get("events"):
            lines.append("- **Eventos:** " + "; ".join(
                f"{event.get('phase')}={event.get('status')}" for event in crew["events"]
            ))
        plan = crew.get("plan") or {}
        if plan.get("rationale"):
            lines.append(f"- **Plan:** {plan['rationale']}")
        validation = crew.get("validation") or {}
        if validation:
            lines.append(f"- **Validación:** consistente={validation.get('consistent')}")
    lines += ["", "## Limitaciones", ""]
    lines += [f"- {lim}" for lim in report["limitations"]]
    lines += ["", "## Recomendaciones", ""]
    lines += [f"- {rec}" for rec in report["recommendations"]]
    lines += [
        "",
        "---",
        f"Generado por ARGOS · LLM: {report['llm'].get('status')} · "
        f"tokens: {report['llm'].get('tokens', 0)} · esquema {report['schema']}",
        "",
    ]
    return "\n".join(lines)


def to_html(report: dict) -> str:
    esc = html.escape
    s = report["sample"]
    rows = "".join(
        f"<tr><td><code>{esc(str(f.get('evidence_id')))}</code></td><td>{esc(str(f.get('tool')))}</td>"
        f"<td>{esc(str(f.get('category')))}</td><td>{esc(str(f.get('description'))[:300])}</td>"
        f"<td>{f.get('score')}</td></tr>"
        for f in report["findings"]
    )
    ioc_rows = "".join(
        f"<tr><td>{esc(i['type'])}</td><td><code>{esc(i['value'])}</code></td><td>{esc(i['verdict'])}</td></tr>"
        for i in report["iocs"]
    )
    chain = "".join(f"<li>{esc(step)}</li>" for step in report["attack_chain"])
    mitre = "".join(f"<li><b>{esc(m['technique'])}</b> — {esc(m['name'])}</li>" for m in report["mitre"])
    limits = "".join(f"<li>{esc(x)}</li>" for x in report["limitations"])
    recs = "".join(f"<li>{esc(x)}</li>" for x in report["recommendations"])
    crew = report.get("crew") or {}
    crew_html = ""
    if crew.get("status") not in (None, "disabled"):
        agents = ", ".join(crew.get("agents") or []) or "—"
        events = "; ".join(
            f"{event.get('phase')}={event.get('status')}" for event in crew.get("events", [])
        ) or "—"
        crew_html = (
            "<h2>Agentes (CrewAI)</h2>"
            f"<p><b>Estado:</b> {esc(str(crew.get('status')))} · "
            f"<b>Tokens:</b> {crew.get('tokens', 0)} · "
            f"<b>Duración:</b> {crew.get('duration_ms', 0)} ms</p>"
            f"<p><b>Agentes:</b> {esc(agents)}</p>"
            f"<p><b>Eventos:</b> {esc(events)}</p>"
        )
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>Informe ARGOS</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#111}}
h1{{border-bottom:3px solid #111;padding-bottom:.4rem}}
.badge{{display:inline-block;padding:.2rem .6rem;border-radius:4px;background:#eee;font-weight:600}}
.malicious{{background:#ffd7d7}} .suspicious{{background:#ffe9c7}}
.benign{{background:#d9f2d9}} .inconclusive{{background:#e2e2e2}}
table{{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.9rem}}
td,th{{border:1px solid #ccc;padding:.35rem .5rem;text-align:left;vertical-align:top}}
code{{background:#f3f3f3;padding:.1rem .25rem;border-radius:3px;font-size:.85em}}
</style></head><body>
<h1>Informe ARGOS</h1>
<p><span class="badge {esc(report['verdict'])}">{esc(report['verdict'])}</span>
confianza {report['confidence']} · riesgo {report['risk_score']}/10</p>
<p><b>Archivo:</b> {esc(str(s.get('filename')))}<br>
<b>SHA-256:</b> <code>{esc(str(s.get('sha256')))}</code><br>
<b>Tipo:</b> {esc(str(s.get('detected_type')))} · <b>Tamaño:</b> {s.get('size')} bytes</p>
<h2>Resumen</h2><p>{esc(report['summary'])}</p>
<h2>Cadena de ataque (inferida)</h2><ol>{chain or '<li>Sin cadena inferida</li>'}</ol>
<h2>Hallazgos</h2>
<table><tr><th>Evidencia</th><th>Herramienta</th><th>Categoría</th><th>Descripción</th><th>Score</th></tr>{rows}</table>
<h2>IOCs</h2>
<table><tr><th>Tipo</th><th>Valor (defanged)</th><th>Veredicto</th></tr>
{ioc_rows or '<tr><td colspan=3>Sin IOCs</td></tr>'}</table>
<h2>MITRE ATT&amp;CK</h2><ul>{mitre or '<li>Sin técnicas mapeadas</li>'}</ul>
<h2>Limitaciones</h2><ul>{limits}</ul>
<h2>Recomendaciones</h2><ul>{recs}</ul>
{crew_html}
<hr><p style="font-size:.8rem;color:#555">Generado por ARGOS · esquema {esc(report['schema'])} ·
LLM: {esc(str(report['llm'].get('status')))} · tokens: {report['llm'].get('tokens', 0)}</p>
</body></html>"""
