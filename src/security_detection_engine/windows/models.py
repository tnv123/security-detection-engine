from datetime import datetime

from pydantic import BaseModel, Field, field_validator

RESERVED_EVENT_DATA = frozenset({"provider", "event_id"})


class WindowsEventRecord(BaseModel):
    """Промежуточная модель события Windows Event Log, извлечённого из XML."""

    event_id: int = Field(gt=0)
    timestamp: datetime
    computer: str | None = None
    provider: str | None = None
    event_data: dict[str, str] = Field(default_factory=dict)

    @field_validator("event_data")
    @classmethod
    def check_names(cls, value: dict[str, str]) -> dict[str, str]:
        if RESERVED_EVENT_DATA.intersection(value):
            raise ValueError("Зарезервированное имя EventData")
        return value

    @field_validator("computer")
    @classmethod
    def strip_computer(cls, value: str | None) -> str | None:
        return (value.strip() or None) if value else None

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp должен содержать информацию о часовом поясе")
        return value
