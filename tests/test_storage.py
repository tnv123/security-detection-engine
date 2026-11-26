from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.dialects.postgresql import dialect
from sqlalchemy.schema import CreateTable

from security_detection_engine.config import Settings
from security_detection_engine.models import EventSource, SecurityEvent
from security_detection_engine.storage import create_database_engine
from security_detection_engine.storage.mapper import event_to_row
from security_detection_engine.storage.models import Base, EventRow
from security_detection_engine.storage.revision import EXPECTED_REVISION


def test_expected_revision_matches_alembic_head():
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    scripts = ScriptDirectory.from_config(config)

    assert scripts.get_heads() == [EXPECTED_REVISION]


def test_database_configuration(monkeypatch):
    monkeypatch.setenv("SDE_DATABASE_URL", "postgresql+psycopg://localhost/sde_test")
    assert Settings().database_url.endswith("/sde_test")
    engine = create_database_engine()
    assert engine.dialect.name == "postgresql"
    engine.dispose()


def test_missing_database_configuration(monkeypatch):
    monkeypatch.delenv("SDE_DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="SDE_DATABASE_URL"):
        create_database_engine()


def test_json_conversion_and_timestamp():
    event = SecurityEvent(
        timestamp=datetime(2024, 1, 1, tzinfo=timezone(timedelta(hours=3))),
        source=EventSource.LINUX,
        event_type="example",
        data={"id": uuid4(), "at": datetime(2024, 1, 1, tzinfo=UTC)},
    )
    row = event_to_row(event)
    assert row.timestamp == event.timestamp
    assert row.data == event.model_dump(mode="json")["data"]
    assert isinstance(event.data["at"], datetime)


def test_schema_compiles_for_postgresql():
    for table in Base.metadata.sorted_tables:
        assert str(CreateTable(table).compile(dialect=dialect()))
    ddl = str(CreateTable(EventRow.__table__).compile(dialect=dialect()))
    assert "JSONB" in ddl
    assert "TIMESTAMP WITH TIME ZONE" in ddl
