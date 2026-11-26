from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_serializer, field_validator

from security_detection_engine.models.values import finite_values


class EventSource(StrEnum):
    """Источник события безопасности."""

    LINUX = "linux"
    WINDOWS = "windows"
    NETWORK = "network"


class Severity(StrEnum):
    """Уровень важности события."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    """Нормализованное событие безопасности из любого источника данных."""

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    source: EventSource
    event_type: str = Field(min_length=1)
    severity: Severity | None = None
    host: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)

    _finite = field_validator("data")(finite_values)

    @field_serializer("data", when_used="json")
    def serialize_data(self, value: dict[str, Any]) -> dict[str, Any]:
        """Повторно проверяет данные после возможной мутации модели."""
        return finite_values(value)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        # Naive datetime неоднозначен при корреляции событий из разных источников.
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp должен содержать информацию о часовом поясе")
        return value

    @field_validator("event_type", "host")
    @classmethod
    def strip_non_empty(cls, value: str | None) -> str | None:
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("значение не должно быть пустой строкой")
        return value


def utc_now() -> datetime:
    """Текущее время в UTC с информацией о часовом поясе."""
    return datetime.now(UTC)
