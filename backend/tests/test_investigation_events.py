from fastapi.testclient import TestClient

from api.main import app


def test_investigation_options_events_and_duplicate_start(clean_db):
    with TestClient(app) as client:
        def create(crew="false", llm="false"):
            return client.post(
                "/investigations",
                files={"file": ("sample.txt", b"a benign sample", "text/plain")},
                data={"enable_llm": llm, "crew_enabled": crew, "strict_privacy": "true"},
            )

        assert create(crew="true").status_code == 422
        first = create().json()
        second = create().json()
        assert first["sample_id"] == second["sample_id"]
        assert first["investigation_id"] != second["investigation_id"]
        inv = first["investigation_id"]
        events = client.get(f"/investigations/{inv}/events").json()
        assert events["items"][0]["message"] == "Investigación creada"
        assert client.get(f"/investigations/{inv}/events", params={"after": events["next_cursor"]}).json()["items"] == []
        response = client.post(f"/investigations/{inv}/start?wait=true")
        assert response.status_code == 202
        assert response.json()["status"] == "done"
        assert client.post(f"/investigations/{inv}/start").status_code == 409
        detail = client.get(f"/investigations/{inv}").json()
        assert detail["options"]["enable_llm"] is False
        assert detail["report"] is not None
        assert len(client.get(f"/investigations/{inv}/events").json()["items"]) >= 3
