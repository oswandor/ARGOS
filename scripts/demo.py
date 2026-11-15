#!/usr/bin/env python
"""Demo end-to-end de ARGOS: genera una muestra sintética, la analiza y guarda el informe.

Uso:
    python scripts/demo.py                # PDF con JavaScript + DOCM embebido
    python scripts/demo.py --benign       # PDF limpio
    python scripts/demo.py --docm         # DOCM con macro de laboratorio
    python scripts/demo.py --file ruta.pdf
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from core.db import SessionLocal, init_db  # noqa: E402
from core.ingest import ingest  # noqa: E402
from core.report import to_html, to_markdown  # noqa: E402
from core.settings import get_settings  # noqa: E402
from core.storage import LocalStorage  # noqa: E402
from graphs.pipeline import Investigator  # noqa: E402
from tests.fixtures.pdf_factory import benign_pdf, docm_bytes, malicious_pdf  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benign", action="store_true")
    parser.add_argument("--docm", action="store_true")
    parser.add_argument("--file", type=Path)
    args = parser.parse_args()

    if args.file:
        data = args.file.read_bytes()
        filename = args.file.name
    elif args.benign:
        data, filename = benign_pdf(), "factura_benigna.pdf"
    elif args.docm:
        data, filename = docm_bytes(), "macro_laboratorio.docm"
    else:
        data, filename = malicious_pdf(with_embedded=True), "factura_2026.pdf"

    settings = get_settings()
    init_db()
    db = SessionLocal()
    try:
        storage = LocalStorage(settings.blob_dir)
        sample, deduplicated = ingest(db, storage, settings, filename=filename, data=data)
        db.commit()
        print(f"Muestra: {sample.id} · {filename} · {sample.detected_type} · sha256={sample.sha256[:16]}…")
        print(f"Deduplicada: {deduplicated}")

        investigator = Investigator(db)
        investigation = investigator.run(sample)
        if investigation.status != "done":
            print(f"FALLO: {investigation.error}", file=sys.stderr)
            return 1

        report = json.loads(investigation.report_json)
        out_dir = ROOT / "reports" / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = sample.sha256[:16]
        (out_dir / f"{stem}.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        (out_dir / f"{stem}.md").write_text(to_markdown(report), encoding="utf-8")
        (out_dir / f"{stem}.html").write_text(to_html(report), encoding="utf-8")

        print()
        print(
            f"Veredicto : {report['verdict'].upper()}  "
            f"(confianza {report['confidence']}, riesgo {report['risk_score']}/10)"
        )
        print(f"Hallazgos : {len(report['findings'])}")
        print(f"IOCs      : {len(report['iocs'])}")
        print(f"Hijos     : {len(report['children'])}")
        print(f"Cobertura : {', '.join(report['coverage']['executed'])}")
        print(f"LLM       : {report['llm']['status']}")
        print()
        print("Resumen:")
        print(" ", report["summary"])
        print()
        print(f"Informes en: {out_dir}")
        for ext in ("json", "md", "html"):
            print(f"  - {out_dir / f'{stem}.{ext}'}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
