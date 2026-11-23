import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

from security_detection_engine.correlation import (
    CorrelationEngine,
    load_correlation_rules_from_directory,
)
from security_detection_engine.detection import (
    DetectionEngine,
    load_rules_from_directory,
)
from security_detection_engine.models import EventSource, SecurityEvent
from security_detection_engine.pipeline import Pipeline
from security_detection_engine.storage import (
    AlertRepository,
    CorrelationAlertRepository,
    EventRepository,
    PipelineResultStore,
    create_database_engine,
    create_session_factory,
    transaction,
)

pytestmark = pytest.mark.postgresql
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def database(monkeypatch):
    url = os.environ.get("SDE_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Задайте SDE_TEST_DATABASE_URL для отдельной тестовой PostgreSQL")
    admin = create_database_engine(url)
    schema = "sde_test_" + uuid4().hex
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    migration_url = make_url(url).update_query_dict(
        {"options": f"-csearch_path={schema}"}
    )
    engine = create_database_engine(migration_url.render_as_string(hide_password=False))
    monkeypatch.setenv(
        "SDE_DATABASE_URL", migration_url.render_as_string(hide_password=False)
    )
    config = Config(str(ROOT / "alembic.ini"))
    try:
        command.upgrade(config, "head")
        yield create_session_factory(engine), config
    finally:
        engine.dispose()
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.fixture
def batch():
    events = [
        SecurityEvent(
            timestamp=datetime(2024, 1, 1, tzinfo=timezone(timedelta(hours=3)))
            + timedelta(seconds=i),
            source=EventSource.LINUX,
            event_type="ssh_authentication_failed"
            if i < 3
            else "ssh_authentication_success",
            data={
                "authentication_method": "password",
                "source_ip": "192.0.2.1",
                "nested": {"items": [1, True, None, "тест"]},
            },
        )
        for i in range(4)
    ]
    rules = ROOT / "src/security_detection_engine/rules"
    result = Pipeline(
        DetectionEngine(load_rules_from_directory(rules)),
        CorrelationEngine(load_correlation_rules_from_directory(rules / "correlation")),
    ).process(events)
    return events, result


def test_roundtrip_pipeline(database, batch):
    factory, _ = database
    events, result = batch
    with transaction(factory) as session:
        PipelineResultStore(session).save(iter(events), result)
    with transaction(factory) as session:
        repository = EventRepository(session)
        assert repository.get(events[0].event_id) == events[0]
        assert repository.list() == events
        assert (
            AlertRepository(session).get(result.alerts[0].alert_id) == result.alerts[0]
        )
        assert AlertRepository(session).list() == result.alerts
        correlations = CorrelationAlertRepository(session)
        assert (
            correlations.get(result.correlation_alerts[0].correlation_id)
            == result.correlation_alerts[0]
        )
        assert correlations.list() == result.correlation_alerts
        assert correlations.list()[0].event_ids == [e.event_id for e in events]
        assert repository.get(uuid4()) is None
        assert AlertRepository(session).get(uuid4()) is None
        assert correlations.get(uuid4()) is None


def test_filters_and_pagination(database, batch):
    factory, _ = database
    events, result = batch
    with transaction(factory) as session:
        PipelineResultStore(session).save(events, result)
    with transaction(factory) as session:
        repo = EventRepository(session)
        assert repo.list(limit=2, offset=1) == events[1:3]
        assert repo.list(source=EventSource.WINDOWS) == []
        assert (
            repo.list(
                source=EventSource.LINUX,
                event_type=events[0].event_type,
                start_timestamp=events[1].timestamp,
                end_timestamp=events[2].timestamp,
            )
            == events[1:3]
        )
        assert AlertRepository(session).list(limit=1, offset=1) == result.alerts[1:2]
        assert CorrelationAlertRepository(session).list(offset=1) == []
        with pytest.raises(ValueError):
            repo.list(limit=0)
        with pytest.raises(ValueError):
            repo.list(start_timestamp=datetime(2024, 1, 1))


@pytest.mark.parametrize("kind", ["event", "alert", "correlation"])
def test_duplicate_uuid_rolls_back(database, batch, kind):
    factory, _ = database
    events, result = batch
    with transaction(factory) as session:
        PipelineResultStore(session).save(events, result)
    extra = events[0].model_copy(update={"event_id": uuid4()})
    with pytest.raises(IntegrityError), transaction(factory) as session:
        EventRepository(session).save(extra)
        if kind == "event":
            EventRepository(session).save(events[0])
        elif kind == "alert":
            AlertRepository(session).save(result.alerts[0])
        else:
            CorrelationAlertRepository(session).save(result.correlation_alerts[0])
    with transaction(factory) as session:
        assert EventRepository(session).get(extra.event_id) is None
        assert EventRepository(session).get(events[0].event_id) == events[0]


@pytest.mark.parametrize("kind", ["alert", "correlation"])
def test_missing_reference_rolls_back_entire_batch(database, batch, kind):
    factory, _ = database
    events, result = batch
    if kind == "alert":
        result.alerts[0].event_id = uuid4()
    else:
        result.correlation_alerts[0].event_ids[0] = uuid4()
    with pytest.raises(IntegrityError), transaction(factory) as session:
        PipelineResultStore(session).save(events, result)
    with transaction(factory) as session:
        assert EventRepository(session).list() == []
        assert AlertRepository(session).list() == []
        assert CorrelationAlertRepository(session).list() == []


def test_existing_event_reference_and_migrations(database, batch):
    factory, config = database
    events, result = batch
    with transaction(factory) as session:
        EventRepository(session).save(events[0])
    result.event_count -= 1
    with transaction(factory) as session:
        PipelineResultStore(session).save(events[1:], result)
    command.check(config)
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    with transaction(factory) as session:
        assert EventRepository(session).list() == []
