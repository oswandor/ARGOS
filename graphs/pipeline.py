"""Pipeline de investigación ARGOS (MVP).

Determinista en la ejecución de herramientas; el LLM solo redacta. Cada muestra
y cada artefacto hijo pasan por el registro de herramientas con allowlist.
"""

from __future__ import annotations

import json
import logging
import traceback
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agents.crew import CrewResult, crew_available, run_crew
from core.hashing import sha256_bytes
from core.llm import review as llm_review
from core.models import IOC, Artifact, Evidence, Investigation, IOCOccurrence, Sample, ToolRun, new_id
from core.policy import ALLOWLIST, Budget, BudgetExceeded, PolicyError
from core.report import build_report
from core.sanitizer import defang
from core.scoring import aggregate
from core.settings import Settings, get_settings
from core.storage import LocalStorage, artifact_key
from tools import registry
from tools.adapters.triage import detect
from tools.base import ToolContext, ToolOutput
from tools.bootstrap import register_all

TOOLS_BY_TYPE: dict[str, list[str]] = {
    "pdf": ["pdfid", "pdf_parser"],
    "office": ["office_scan"],
    "javascript": ["js_analyzer"],
    "shellcode": ["shellcode"],
    "pe": ["shellcode"],
}

MAX_IOCS = 200
IOC_TYPES = {"url", "domain", "ip", "email", "hash"}
CONTENT_TOOLS = {"pdfid", "pdf_parser", "js_analyzer", "office_scan", "shellcode"}
logger = logging.getLogger("argos.pipeline")


def _now() -> datetime:
    return datetime.now(UTC)


class Investigator:
    def __init__(self, db: Session, settings: Settings | None = None) -> None:
        register_all()
        self.db = db
        self.settings = settings or get_settings()
        self.storage = LocalStorage(self.settings.blob_dir)
        self.budget = Budget(
            max_children=self.settings.max_children,
            max_depth=self.settings.max_depth,
        )
        self.evidence: list[dict] = []
        self.tool_outputs: list[dict] = []
        self.coverage: dict[str, list[str]] = {
            "executed": [],
            "skipped": [],
            "unavailable": [],
            "errors": [],
        }
        self.iocs: dict[str, dict] = {}
        self.warnings: list[str] = []
        self.timings: dict[str, int] = {}
        self.children: list[dict] = []
        self.investigation_id = ""
        self.sample: Sample | None = None
        self._analyzed_tools: set[tuple[str, str]] = set()
        self._yara_rules: set[str] = set()
        self.crew_meta: dict = {
            "status": "disabled",
            "agents": [],
            "tokens": 0,
            "duration_ms": 0,
        }
        self._crew_calls = 0

    # ------------------------------------------------------------------ run
    def run(self, sample: Sample) -> Investigation:
        investigation = Investigation(sample_id=sample.id, status="running")
        self.db.add(investigation)
        self.db.flush()
        self.investigation_id = investigation.id
        sample.status = "analyzing"
        logger.info(
            "investigation.start id=%s sample=%s type=%s size=%s sha256=%s",
            investigation.id,
            sample.filename,
            sample.detected_type,
            sample.size,
            sample.sha256,
        )

        try:
            self.sample = sample
            crew_result = self._crew_phase(sample)
            self._lookup_intel(sample)

            assessment = aggregate(
                self.evidence,
                self.coverage,
                sample.detected_type,
                self.warnings,
            )
            if crew_result and crew_result.validation and not crew_result.validation.get(
                "consistent", True
            ):
                contradictions = crew_result.validation.get("contradictions") or []
                assessment.limitations.append(
                    "El validador detectó contradicciones o huecos: "
                    + "; ".join(str(c) for c in contradictions[:3])
                )
                assessment.confidence = round(max(0.3, assessment.confidence - 0.03), 2)
                for claim in (crew_result.validation.get("unsupported_claims") or [])[:3]:
                    assessment.limitations.append(f"Afirmación sin evidencia suficiente: {claim}")

            llm_out, llm_meta = self._inference_pass(crew_result, assessment, sample)
            if llm_out:
                delta = float(llm_out.get("confidence_adjustment", 0.0))
                assessment.confidence = round(
                    max(0.3, min(0.95, assessment.confidence + max(-0.05, min(0.05, delta)))), 2
                )

            report = build_report(
                investigation_id=investigation.id,
                sample={
                    "id": sample.id,
                    "filename": sample.filename,
                    "sha256": sample.sha256,
                    "md5": sample.md5,
                    "size": sample.size,
                    "mime": sample.mime,
                    "detected_type": sample.detected_type,
                    "parent_id": sample.parent_id,
                    "depth": sample.depth,
                },
                children=self.children,
                assessment=assessment,
                evidence=self.evidence,
                tool_outputs=self.tool_outputs,
                iocs=list(self.iocs.values()),
                coverage=self.coverage,
                llm_meta=llm_meta,
                llm_review=llm_out,
                crew_meta=self.crew_meta,
                timings=self.timings,
            )

            investigation.verdict = assessment.verdict
            investigation.confidence = assessment.confidence
            investigation.risk_score = assessment.risk_score
            investigation.llm_status = str(llm_meta.get("status", "disabled"))
            investigation.tokens_used = int(llm_meta.get("tokens", 0) or 0)
            investigation.report_json = json.dumps(report, ensure_ascii=False)
            investigation.status = "done"
            investigation.finished_at = _now()
            sample.status = "analyzed"
            sample.meta = json.dumps(
                {
                    "tool_versions": {o["tool"]: o["version"] for o in self.tool_outputs},
                    "coverage": self.coverage,
                },
                ensure_ascii=False,
            )
            self._persist_iocs()
            logger.info(
                "investigation.end id=%s verdict=%s confidence=%s risk=%s evidence=%s "
                "iocs=%s crew=%s tokens=%s",
                investigation.id,
                assessment.verdict,
                assessment.confidence,
                assessment.risk_score,
                len(self.evidence),
                len(self.iocs),
                self.crew_meta.get("status"),
                investigation.tokens_used,
            )
        except Exception as exc:  # noqa: BLE001 - la investigación falla, el proceso no
            investigation.status = "failed"
            investigation.error = f"{type(exc).__name__}: {exc}"[:2000]
            investigation.finished_at = _now()
            sample.status = "failed"
            self.warnings.append(traceback.format_exc()[-3000:])
        self.db.commit()
        return investigation

    # -------------------------------------------------------------- análisis
    def _analyze(
        self, sample: Sample, *, depth: int = 0, tools: list[str] | None = None
    ) -> None:
        if tools is None:
            tools = ["yara", *TOOLS_BY_TYPE.get(sample.detected_type, [])]
            if sample.detected_type not in TOOLS_BY_TYPE:
                self.coverage["skipped"].append(f"{sample.filename}:{sample.detected_type}")

        data = self.storage.get(sample.storage_key)
        ctx = ToolContext(
            sample_id=sample.id,
            filename=sample.filename,
            detected_type=sample.detected_type,
            data=data,
            meta={
                "max_js_bytes": self.settings.max_js_bytes,
                "max_streams": self.settings.max_streams,
            },
        )

        for tool_id in tools:
            key = (sample.id, tool_id)
            if key in self._analyzed_tools:
                continue
            self._analyzed_tools.add(key)
            try:
                output = registry.run(tool_id, ctx, self.budget, is_child=depth > 0)
            except PolicyError as exc:
                self.coverage["skipped"].append(tool_id)
                self.warnings.append(str(exc))
                continue
            except BudgetExceeded as exc:
                self.warnings.append(str(exc))
                break

            self._record(sample, output)
            if output.artifacts:
                self._handle_artifacts(sample, output, depth)

    # ---------------------------------------------------------------- crew
    def _crew_phase(self, sample: Sample) -> CrewResult | None:
        """Ejecuta el crew si está disponible; si no, plan determinista completo."""
        if not crew_available(self.settings):
            self._analyze(sample)
            return None

        result = run_crew(self, self.settings, ensure_evidence=lambda: self._ensure_evidence(sample))
        self.crew_meta = {
            "status": result.status,
            "agents": result.agents,
            "tokens": result.tokens,
            "duration_ms": result.duration_ms,
            "plan": result.plan,
            "families": result.families,
            "validation": result.validation,
            "errors": result.errors[:5],
            "events": result.events,
        }
        for error in result.errors[:3]:
            self.warnings.append(f"crew: {error}")

        if not self._has_content_tools():
            self.warnings.append(
                "El crew no ejecutó herramientas de contenido; se aplica el plan "
                "determinista de respaldo"
            )
            self._analyze(sample)
        return result

    def _ensure_evidence(self, sample: Sample) -> None:
        """Respaldo determinista entre las dos fases del crew."""
        if not self._has_content_tools():
            self.warnings.append(
                "El supervisor no ejecutó herramientas de contenido; respaldo determinista"
            )
            self._analyze(sample)

    def _has_content_tools(self) -> bool:
        return any(tool in CONTENT_TOOLS for tool in self.coverage["executed"])

    def _inference_pass(
        self, crew_result: CrewResult | None, assessment, sample: Sample
    ) -> tuple[dict | None, dict]:
        """Narrativa del crew o, en su defecto, redactor único o plantilla."""
        if crew_result and crew_result.ok and crew_result.narrative:
            return crew_result.narrative, {
                "status": "ok",
                "mode": "crew",
                "model": self.settings.crew_model or "deepseek-chat",
                "tokens": crew_result.tokens,
                "duration_ms": crew_result.duration_ms,
                "agents": crew_result.agents,
            }
        if crew_result is not None and not crew_result.ok:
            self.warnings.append("CrewAI no produjo un informe válido; se usa el redactor único")
        out, meta = self._llm_pass(assessment, sample)
        meta["mode"] = "single_fallback" if crew_result is not None else "single"
        if crew_result is not None:
            meta["crew_status"] = crew_result.status
        return out, meta

    def execute_tool_for_crew(self, tool_id: str) -> dict:
        """Herramienta `run_analysis` del supervisor: revalida y ejecuta."""
        sample = self.sample
        if sample is None:
            return {"status": "error", "error": "sin muestra activa"}
        if tool_id not in ALLOWLIST.get(sample.detected_type, ALLOWLIST["unknown"]):
            return {"status": "rejected", "error": f"'{tool_id}' no permitida para este tipo"}
        if tool_id in {"triage", "intel"}:
            return {"status": "rejected", "error": "herramienta reservada al backend"}
        if (sample.id, tool_id) in self._analyzed_tools:
            return {"status": "skipped", "note": "herramienta ya ejecutada en esta investigación"}
        if self._crew_calls >= self.settings.crew_max_tool_calls:
            return {"status": "rejected", "error": "presupuesto de herramientas del crew agotado"}

        self._crew_calls += 1
        logger.info("crew.tool.start tool=%s sample_type=%s call=%s", tool_id, sample.detected_type, self._crew_calls)
        data = self.storage.get(sample.storage_key)
        ctx = ToolContext(
            sample_id=sample.id,
            filename=sample.filename,
            detected_type=sample.detected_type,
            data=data,
            meta={
                "max_js_bytes": self.settings.max_js_bytes,
                "max_streams": self.settings.max_streams,
            },
        )
        try:
            output = registry.run(tool_id, ctx, self.budget)
        except (PolicyError, BudgetExceeded) as exc:
            return {"status": "rejected", "error": str(exc)}

        self._analyzed_tools.add((sample.id, tool_id))
        self._record(sample, output)
        if output.artifacts:
            self._handle_artifacts(sample, output, sample.depth)
        result = {
            "status": output.status,
            "tool": tool_id,
            "sandbox": output.sandbox,
            "findings": len(output.findings),
            "categories": sorted({f.category for f in output.findings}),
            "iocs": len(output.data.get("iocs", []) or []),
            "warnings": output.warnings[:3],
        }
        logger.info("crew.tool.end tool=%s status=%s findings=%s sandbox=%s", tool_id, output.status,
                    len(output.findings), output.sandbox)
        return result

    def _record(self, sample: Sample, output: ToolOutput) -> None:
        run = ToolRun(
            investigation_id=self.investigation_id,
            tool_id=output.tool_id,
            tool_version=output.tool_version,
            status=output.status,
            duration_ms=output.duration_ms,
            warnings=json.dumps(output.warnings[:10], ensure_ascii=False),
        )
        self.db.add(run)
        self.timings[output.tool_id] = self.timings.get(output.tool_id, 0) + output.duration_ms

        if output.status in {"ok", "partial"}:
            if output.tool_id not in self.coverage["executed"]:
                self.coverage["executed"].append(output.tool_id)
        elif output.status == "unavailable":
            if output.tool_id not in self.coverage["unavailable"]:
                self.coverage["unavailable"].append(output.tool_id)
        else:
            if output.tool_id not in self.coverage["errors"]:
                self.coverage["errors"].append(output.tool_id)
        for warning in output.warnings[:5]:
            if warning not in self.warnings:
                self.warnings.append(warning)

        for finding in output.findings:
            # Una regla YARA que ya disparó en otro artefacto de la misma
            # investigación no se duplica como evidencia.
            if output.tool_id == "yara":
                if finding.description in self._yara_rules:
                    continue
                self._yara_rules.add(finding.description)

            evidence_id = new_id("ev")
            self.db.add(
                Evidence(
                    id=evidence_id,
                    investigation_id=self.investigation_id,
                    sample_id=sample.id,
                    tool=output.tool_id,
                    category=finding.category,
                    object_id=finding.object_id or "",
                    description=finding.description,
                    suspicious=finding.suspicious,
                    score=float(finding.score),
                    raw_ref=finding.raw_ref or "",
                )
            )
            self.evidence.append(
                {
                    "evidence_id": evidence_id,
                    "sample_id": sample.id,
                    "tool": output.tool_id,
                    "category": finding.category,
                    "object_id": finding.object_id or "",
                    "description": finding.description,
                    "suspicious": finding.suspicious,
                    "score": round(float(finding.score), 2),
                }
            )

        for item in output.data.get("iocs", []) or []:
            if isinstance(item, dict) and item.get("value"):
                self._add_ioc(str(item.get("type", "unknown")), str(item["value"]))

        summary = output.summary()
        summary["data"] = {k: v for k, v in summary["data"].items() if k not in {"iocs", "preview"}}
        if "preview" in output.data:
            summary["data"]["preview"] = str(output.data["preview"])[:300]
        self.tool_outputs.append(summary)

    # ------------------------------------------------------------- artefactos
    def _handle_artifacts(self, parent: Sample, output: ToolOutput, depth: int) -> None:
        for artifact in output.artifacts[: self.settings.max_children]:
            if not artifact.data:
                continue
            if len(artifact.data) > self.settings.max_artifact_bytes:
                self.warnings.append(
                    f"Artefacto {artifact.kind} omitido: {len(artifact.data)} bytes supera el límite"
                )
                continue
            digest = sha256_bytes(artifact.data)
            key = artifact_key(digest, artifact.kind)
            self.storage.put(key, artifact.data)

            # VBA y archivos generados por emulación se guardan como artefactos,
            # no como muestras hijas: evita recursión y re-emulación en cascada.
            if artifact.kind in {"vba", "dropped"}:
                self.db.add(
                    Artifact(
                        sample_id=parent.id,
                        kind=artifact.kind,
                        sha256=digest,
                        size=len(artifact.data),
                        storage_key=key,
                    )
                )
                continue

            existing = self.db.scalar(select(Sample).where(Sample.sha256 == digest))
            if existing:
                self.db.add(
                    Artifact(
                        sample_id=parent.id,
                        kind=artifact.kind,
                        sha256=digest,
                        size=len(artifact.data),
                        storage_key=key,
                        child_sample_id=existing.id,
                    )
                )
                # El hijo ya existe en la BD (otra investigación): se reutiliza la
                # muestra pero se vuelve a analizar dentro de esta investigación.
                self._analyze(existing, depth=existing.depth)
                self.children.append(
                    {
                        "sample_id": existing.id,
                        "filename": existing.filename,
                        "sha256": digest,
                        "type": existing.detected_type,
                        "size": existing.size,
                        "origin": artifact.kind,
                        "depth": existing.depth,
                        "reused": True,
                    }
                )
                continue

            if depth + 1 > self.settings.max_depth:
                self.warnings.append(
                    f"Profundidad máxima ({self.settings.max_depth}) alcanzada; "
                    f"artefacto {artifact.kind} no analizado"
                )
                continue
            try:
                self.budget.spend_child()
            except BudgetExceeded as exc:
                self.warnings.append(str(exc))
                break

            child_type, child_mime, _ = detect(artifact.data, artifact.filename)
            child = Sample(
                id=new_id("smp"),
                sha256=digest,
                md5="",
                size=len(artifact.data),
                filename=artifact.filename or f"artefacto_{digest[:12]}.bin",
                extension=(artifact.filename.rsplit(".", 1)[-1].lower() if "." in artifact.filename else ""),
                detected_type=child_type,
                mime=child_mime,
                storage_key=key,
                parent_id=parent.id,
                depth=depth + 1,
                status="received",
                meta=json.dumps({"origin": artifact.kind, "note": artifact.note}),
            )
            self.db.add(child)
            self.db.flush()
            self.db.add(
                Artifact(
                    sample_id=parent.id,
                    kind=artifact.kind,
                    sha256=digest,
                    size=len(artifact.data),
                    storage_key=key,
                    child_sample_id=child.id,
                )
            )
            self.children.append(
                {
                    "sample_id": child.id,
                    "filename": child.filename,
                    "sha256": digest,
                    "type": child_type,
                    "size": len(artifact.data),
                    "origin": artifact.kind,
                    "depth": child.depth,
                }
            )
            self._analyze(child, depth=child.depth)

    # ------------------------------------------------------------------ IOCs
    def _add_ioc(self, ioc_type: str, value: str) -> None:
        value = value.strip()
        if ioc_type not in IOC_TYPES:
            return
        if not value or len(value) > 500:
            return
        key = f"{ioc_type}:{value.lower()}"
        if key in self.iocs or len(self.iocs) >= MAX_IOCS:
            return
        self.iocs[key] = {
            "type": ioc_type,
            "value": value,
            "defanged": defang(value, ioc_type),
            "verdict": "unknown",
            "known": False,
        }

    def _lookup_intel(self, sample: Sample) -> None:
        if not self.iocs:
            return
        ctx = ToolContext(
            sample_id=sample.id,
            filename=sample.filename,
            detected_type="unknown",
            data=b"",
            meta={"iocs": [{"type": i["type"], "value": i["value"]} for i in self.iocs.values()]},
        )
        try:
            output = registry.run("intel", ctx, self.budget)
        except (PolicyError, BudgetExceeded) as exc:
            self.warnings.append(str(exc))
            return
        self._record(sample, output)
        known: dict[str, dict] = {}
        for result in output.data.get("results", []):
            known[f"{result['type']}:{str(result['value']).lower()}"] = result
        for key, ioc in self.iocs.items():
            hit = known.get(key)
            if hit and hit.get("known"):
                ioc["known"] = True
                ioc["verdict"] = hit.get("verdict", "unknown")

    def _persist_iocs(self) -> None:
        first_evidence = self.evidence[0]["evidence_id"] if self.evidence else ""
        for ioc in self.iocs.values():
            row = self.db.scalar(
                select(IOC).where(IOC.type == ioc["type"], IOC.value == ioc["value"])
            )
            if row is None:
                row = IOC(
                    type=ioc["type"],
                    value=ioc["value"],
                    defanged=ioc["defanged"],
                    verdict=ioc["verdict"],
                    source="analysis",
                )
                self.db.add(row)
                self.db.flush()
            elif ioc["known"]:
                row.verdict = ioc["verdict"]
            self.db.add(
                IOCOccurrence(
                    ioc_id=row.id,
                    evidence_id=first_evidence,
                    investigation_id=self.investigation_id,
                )
            )

    # ------------------------------------------------------------------- LLM
    def _llm_pass(self, assessment: Any, sample: Sample) -> tuple[dict, dict | None]:
        bundle = {
            "archivo": {
                "nombre": sample.filename,
                "sha256": sample.sha256,
                "tipo": sample.detected_type,
                "bytes": sample.size,
            },
            "veredicto_determinista": assessment.verdict,
            "riesgo": assessment.risk_score,
            "confianza": assessment.confidence,
            "hallazgos": [
                {
                    "herramienta": e["tool"],
                    "categoria": e["category"],
                    "descripcion": e["description"],
                    "score": e["score"],
                }
                for e in self.evidence
            ],
            "iocs": [
                {"tipo": i["type"], "valor": i["defanged"], "veredicto": i["verdict"]}
                for i in self.iocs.values()
            ][:60],
            "cobertura": self.coverage,
            "limitaciones": assessment.limitations,
        }
        return llm_review(bundle, self.settings)
