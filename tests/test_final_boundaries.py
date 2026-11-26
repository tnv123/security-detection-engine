from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError
from pydantic_core import PydanticSerializationError
from test_api_postgresql import client as client
from test_storage_postgresql import database as database

from security_detection_engine.models import SecurityEvent
from security_detection_engine.storage import EventRepository, transaction
from security_detection_engine.storage.mapper import event_to_row


@pytest.mark.parametrize(
    "key",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        Decimal("NaN"),
        Decimal("Infinity"),
        Decimal("-Infinity"),
    ],
)
def test_nonfinite_dictionary_keys(key):
    values = dict(timestamp=datetime.now(UTC), source="linux", event_type="x")
    with pytest.raises(ValidationError):
        SecurityEvent(**values, data={"nested": {key: 1}})
    event = SecurityEvent(**values)
    event.data["nested"] = {key: 1}
    with pytest.raises(PydanticSerializationError):
        event.model_dump(mode="json")
    with pytest.raises(ValidationError):
        event_to_row(event)


@pytest.mark.postgresql
@pytest.mark.parametrize(
    ("depth", "expected"),
    [
        (10, 200),
        (50, 200),
        (100, 422),
        (200, 422),
        (500, 422),
        (1000, 400),
    ],
)
def test_nested_json_safe_failure(client, depth, expected):
    raw = (
        '{"events":[{"timestamp":"2024-01-01T00:00:00Z","source":"linux",'
        '"event_type":"x","data":{"value":' + "[" * depth + "0" + "]" * depth + "}}]}"
    )
    assert len(raw) < 5242880
    response = client.post(
        "/analyze", content=raw, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == expected
    assert len(client.get("/events").json()) == (1 if expected == 200 else 0)
    assert client.get("/health").status_code == 200
    assert client.post("/analyze", json={"events": []}).status_code == 200


@pytest.mark.postgresql
@pytest.mark.parametrize("key", [float("nan"), float("inf"), Decimal("NaN")])
def test_invalid_key_batch_rollback(database, key):
    factory, _ = database
    good = SecurityEvent(timestamp=datetime.now(UTC), source="linux", event_type="x")
    bad = good.model_copy(deep=True)
    bad.data["nested"] = {key: 0}
    with pytest.raises(ValidationError), transaction(factory) as session:
        repo = EventRepository(session)
        repo.save(good)
        repo.save(bad)
    with transaction(factory) as session:
        assert EventRepository(session).list() == []
