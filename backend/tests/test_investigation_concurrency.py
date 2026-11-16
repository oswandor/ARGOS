from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from time import sleep

from core.ingest import ingest
from core.models import Investigation, InvestigationEvent
from core.settings import get_settings
from core.storage import LocalStorage
from graphs.pipeline import Investigator
from tests.fixtures.pdf_factory import benign_pdf
from tools.base import ToolOutput


def test_parallel_crew_tools_are_serialized(clean_db, monkeypatch):
    settings = get_settings()
    sample, _ = ingest(clean_db, LocalStorage(settings.blob_dir), settings,
                       filename="parallel.pdf", data=benign_pdf())
    investigation = Investigation(sample_id=sample.id, status="running")
    clean_db.add(investigation)
    clean_db.commit()
    investigator = Investigator(clean_db, settings)
    investigator.sample = sample
    investigator.investigation_id = investigation.id
    counter_lock = Lock()
    active = 0
    maximum = 0

    def fake_run(tool_id, ctx, budget):
        nonlocal active, maximum
        with counter_lock:
            active += 1
            maximum = max(maximum, active)
        sleep(0.05)
        with counter_lock:
            active -= 1
        return ToolOutput(status="ok", tool_id=tool_id)

    monkeypatch.setattr("graphs.pipeline.registry.run", fake_run)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(investigator.execute_tool_for_crew, ["pdfid", "yara"]))
    assert maximum == 1
    assert [result["status"] for result in results] == ["ok", "ok"]
    assert clean_db.query(InvestigationEvent).filter_by(investigation_id=investigation.id).count() == 2


def test_service_marks_unexpected_failure(clean_db, monkeypatch):
    from core.service import run_investigation

    settings = get_settings()
    sample, _ = ingest(clean_db, LocalStorage(settings.blob_dir), settings,
                       filename="failure.pdf", data=benign_pdf())
    investigation = Investigation(sample_id=sample.id, status="starting")
    clean_db.add(investigation)
    clean_db.commit()

    def fail(*args, **kwargs):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr("core.service.Investigator.run", fail)
    import pytest
    with pytest.raises(RuntimeError, match="simulated failure"):
        run_investigation(sample.id, investigation.id)
    clean_db.expire_all()
    assert clean_db.get(Investigation, investigation.id).status == "failed"
    assert clean_db.query(InvestigationEvent).filter_by(investigation_id=investigation.id, level="error").count() == 1
