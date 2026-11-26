from datetime import datetime
from typing import Any, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from security_detection_engine.detection.models import Condition
from security_detection_engine.models import Severity
from security_detection_engine.models.values import finite_values


class CorrelationStep(BaseModel):
    """Один шаг корреляционной последовательности.

    Повторяющиеся шаги выражают требование нескольких событий одного типа.
    """

    event_type: str = Field(min_length=1)
    conditions: list[Condition] = Field(default_factory=list)

    @field_validator("event_type")
    @classmethod
    def strip_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("значение не должно быть пустой строкой")
        return value


class CorrelationRule(BaseModel):
    """Правило корреляции событий во временном окне."""

    rule_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    severity: Severity
    enabled: bool = True
    time_window_seconds: int = Field(gt=0)
    group_by: list[str] = Field(min_length=1)
    steps: list[CorrelationStep] = Field(min_length=2)

    @field_validator("rule_id", "name", "description")
    @classmethod
    def strip_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("значение не должно быть пустой строкой")
        return value

    @field_validator("group_by")
    @classmethod
    def validate_group_by_paths(cls, value: list[str]) -> list[str]:
        paths = [path.strip() for path in value]
        for path in paths:
            if not path or any(not part for part in path.split(".")):
                raise ValueError(
                    "group_by должен содержать непустые пути без пустых сегментов"
                )
        return paths


class CorrelationAlert(BaseModel):
    """Результат срабатывания корреляционного правила."""

    correlation_id: UUID = Field(default_factory=uuid4)
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    timestamp: datetime
    event_ids: list[UUID] = Field(min_length=2)
    start_timestamp: datetime
    end_timestamp: datetime
    group_values: dict[str, Any]

    _finite = field_validator("group_values")(finite_values)

    @field_validator("timestamp", "start_timestamp", "end_timestamp")
    @classmethod
    def timestamps_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp должен содержать информацию о часовом поясе")
        return value

    @field_validator("event_ids")
    @classmethod
    def unique_events(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("Повторный UUID в корреляции")
        return value

    @model_validator(mode="after")
    def check_time_consistency(self) -> Self:
        if self.start_timestamp > self.end_timestamp:
            raise ValueError("start_timestamp не может быть позже end_timestamp")
        if self.timestamp != self.end_timestamp:
            raise ValueError("timestamp должен совпадать с end_timestamp")
        return self
