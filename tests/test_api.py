from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import DataError, IntegrityError, OperationalError, SQLAlchemyError

from security_detection_engine.api.app import create_app
from security_detection_engine.api.dependencies import get_pipeline, get_session
from security_detection_engine.config import Settings
from security_detection_engine.models import SecurityEvent
from security_detection_engine.pipeline import PipelineResult


@pytest.fixture
def client():
    app = create_app(Settings(database_url="postgresql+psycopg://localhost/sde_test"))
    with TestClient(app) as client:
        yield client


def test_health_and_openapi(client):
    assert client.get("/health").json() == {"status": "ok", "version": "0.1.0"}
    assert client.get("/docs").status_code == 200
    assert len(client.get("/openapi.json").json()["paths"]) == 9


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"events": [{}]},
        {
            "events": [
                {"timestamp": "2024-01-01", "source": "linux", "event_type": "test"}
            ]
        },
    ],
)
def test_invalid_events(client, payload):
    assert client.post("/analyze", json=payload).status_code == 422


def test_batch_size_limit(client):
    events = [
        SecurityEvent(
            timestamp="2024-01-01T00:00:00Z",
            source="linux",
            event_type="ssh_authentication_success",
        ).model_dump(mode="json")
        for _ in range(1001)
    ]
    response = client.post("/analyze", json={"events": events})
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert len(errors) == 1
    assert errors[0]["loc"] == ["body", "events"]
    assert errors[0]["type"] == "too_long"
    assert errors[0]["ctx"]["max_length"] == 1000
    assert errors[0]["ctx"]["actual_length"] == 1001


def test_bad_json(client):
    assert (
        client.post(
            "/analyze", content="{", headers={"Content-Type": "application/json"}
        ).status_code
        == 422
    )


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 1001},
        {"offset": -1},
        {"source": "unknown"},
        {"start_time": "2024-01-01T00:00:00"},
        {"start_time": "2024-01-02T00:00:00Z", "end_time": "2024-01-01T00:00:00Z"},
    ],
)
def test_invalid_filters(client, params):
    assert client.get("/events", params=params).status_code == 422


@pytest.mark.parametrize(
    "path", ["/events/bad", "/alerts/bad", "/correlation-alerts/bad"]
)
def test_invalid_uuid(client, path):
    assert client.get(path).status_code == 422


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (OperationalError("SECRET SQL", {}, Exception("SECRET PASSWORD")), 503),
        (IntegrityError("SECRET SQL", {}, SimpleNamespace(sqlstate="23505")), 409),
        (IntegrityError("SECRET SQL", {}, SimpleNamespace(sqlstate="23503")), 500),
        (DataError("SECRET SQL", {}, Exception("SECRET PASSWORD")), 400),
        (SQLAlchemyError("SECRET PASSWORD"), 500),
    ],
)
def test_database_errors_are_safe(client, error, status):
    def broken_session():
        raise error

    client.app.dependency_overrides[get_session] = broken_session
    response = client.get("/events")
    assert response.status_code == status
    assert "SECRET" not in response.text


def test_readiness_and_session_cleanup(client):
    sessions = []

    def factory():
        session = MagicMock()
        session.__enter__.return_value = session
        sessions.append(session)
        return session

    client.app.state.session_factory = factory
    pipeline = client.app.state.pipeline
    for _ in range(2):
        assert client.get("/health/ready").json() == {"status": "ready"}
    assert len(sessions) == 2
    assert sessions[0] is not sessions[1]
    for session in sessions:
        session.execute.assert_called_once()
        session.__exit__.assert_called_once()
    assert client.app.state.pipeline is pipeline


def test_readiness_unavailable(client):
    def broken_session():
        raise OperationalError("SECRET", {}, Exception("SECRET"))

    client.app.dependency_overrides[get_session] = broken_session
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert "SECRET" not in response.text


def test_unreachable_server():
    app = create_app(
        Settings(
            database_url=(
                "postgresql+psycopg://sde_test_user@127.0.0.1:1/sde_test?connect_timeout=1"
            ),
        )
    )
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert response.json() == {"detail": "База данных недоступна"}
        assert client.get("/events").status_code == 503


def test_dependency_overrides(client):
    session = MagicMock()
    client.app.dependency_overrides[get_session] = lambda: session
    pipeline = MagicMock()
    pipeline.process.return_value = PipelineResult(
        event_count=0,
        alerts=[],
        correlation_alerts=[],
    )
    client.app.dependency_overrides[get_pipeline] = lambda: pipeline
    response = client.post("/analyze", json={"events": []})
    assert response.status_code == 200
    assert response.json()["event_count"] == 0
    pipeline.process.assert_called_once_with([])
    session.begin.assert_called_once()


@pytest.mark.parametrize("path", ["/events", "/alerts", "/correlation-alerts"])
def test_missing_object(client, path):
    session = MagicMock()
    session.get.return_value = None
    client.app.dependency_overrides[get_session] = lambda: session
    assert client.get(f"{path}/{uuid4()}").status_code == 404
