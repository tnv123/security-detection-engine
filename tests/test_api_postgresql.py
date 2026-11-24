from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from test_storage_postgresql import batch as batch
from test_storage_postgresql import database as database

from security_detection_engine.api.app import create_app
from security_detection_engine.api.dependencies import get_pipeline
from security_detection_engine.config import Settings

pytestmark = pytest.mark.postgresql


@pytest.fixture
def client(database):
    app = create_app(Settings())
    with TestClient(app) as client:
        # Lifespan уже использует URL временной схемы из фикстуры database.
        yield client


def test_empty_and_single_event(client, batch):
    assert client.get("/health/ready").status_code == 200
    empty = client.post("/analyze", json={"events": []})
    assert empty.status_code == 200
    assert empty.json()["event_count"] == 0
    events, _ = batch
    response = client.post(
        "/analyze", json={"events": [events[0].model_dump(mode="json")]}
    )
    assert response.status_code == 200
    assert response.json()["alert_count"] == 1
    assert client.get(f"/events/{events[0].event_id}").json()["event_id"] == str(
        events[0].event_id
    )


def test_pipeline_readback_and_filters(client, batch):
    events, _ = batch
    response = client.post(
        "/analyze", json={"events": [event.model_dump(mode="json") for event in events]}
    )
    assert response.status_code == 200
    result = response.json()
    assert result["alert_count"] == 3
    assert result["correlation_alert_count"] == 1
    assert result["correlation_alerts"][0]["event_ids"] == [
        str(e.event_id) for e in events
    ]
    assert len(client.get("/events", params={"limit": 2, "offset": 1}).json()) == 2
    filtered = client.get(
        "/events",
        params={
            "source": "linux",
            "event_type": events[0].event_type,
            "start_time": events[1].timestamp.isoformat(),
            "end_time": events[2].timestamp.isoformat(),
        },
    ).json()
    assert [e["event_id"] for e in filtered] == [str(e.event_id) for e in events[1:3]]
    assert client.get("/events", params={"source": "windows"}).json() == []
    assert client.get("/alerts").json() == result["alerts"]
    assert client.get("/correlation-alerts").json() == result["correlation_alerts"]
    for alert in result["alerts"]:
        assert client.get(f"/alerts/{alert['alert_id']}").json() == alert
    alert = result["correlation_alerts"][0]
    assert client.get(f"/correlation-alerts/{alert['correlation_id']}").json() == alert
    assert (
        client.get("/alerts", params={"limit": 1, "offset": 1}).json()
        == result["alerts"][1:2]
    )
    for route in ["/events", "/alerts", "/correlation-alerts"]:
        assert client.get(f"{route}/{uuid4()}").status_code == 404


def test_duplicate_uuid_rolls_back_request(client, batch):
    events, _ = batch
    first = events[0].model_dump(mode="json")
    assert client.post("/analyze", json={"events": [first]}).status_code == 200
    extra = events[1].model_dump(mode="json")
    response = client.post("/analyze", json={"events": [extra, first]})
    assert response.status_code == 409
    assert "INSERT" not in response.text
    assert len(client.get("/events").json()) == 1
    assert len(client.get("/alerts").json()) == 1
    assert client.get(f"/events/{extra['event_id']}").status_code == 404
    assert client.post("/analyze", json={"events": [extra]}).status_code == 200


def test_failure_after_event_flush_rolls_back(client, batch):
    events, result = batch
    result.alerts[0].event_id = uuid4()

    class InvalidPipeline:
        def process(self, events):
            return result

    client.app.dependency_overrides[get_pipeline] = InvalidPipeline
    response = client.post(
        "/analyze", json={"events": [event.model_dump(mode="json") for event in events]}
    )
    assert response.status_code == 500
    assert response.json() == {"detail": "Ошибка хранения данных"}
    assert client.get("/events").json() == []
    assert client.get("/alerts").json() == []


def test_batches_are_independent(client, batch):
    events, _ = batch
    for part in [events[:3], events[3:]]:
        response = client.post(
            "/analyze", json={"events": [e.model_dump(mode="json") for e in part]}
        )
        assert response.status_code == 200
        assert response.json()["correlation_alert_count"] == 0
    assert len(client.get("/events").json()) == 4
