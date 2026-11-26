from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

from security_detection_engine.models import Severity
from security_detection_engine.models.values import finite_values


class Operator(StrEnum):
    """Поддерживаемые операторы условий правил обнаружения."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"


class Condition(BaseModel):
    """Условие проверки одного поля события."""

    field: str = Field(min_length=1)
    operator: Operator
    value: Any

    _finite = field_validator("value")(finite_values)

    @field_validator("field")
    @classmethod
    def validate_field_path(cls, value: str) -> str:
        value = value.strip()
        if not value or any(not part for part in value.split(".")):
            raise ValueError("поле должно быть непустым путём без пустых сегментов")
        return value


class DetectionRule(BaseModel):
    """Правило обнаружения подозрительной активности."""

    rule_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    severity: Severity
    event_type: str = Field(min_length=1)
    conditions: list[Condition] = Field(default_factory=list)
    enabled: bool = True

    @field_validator("rule_id", "name", "description", "event_type")
    @classmethod
    def strip_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("значение не должно быть пустой строкой")
        return value


class Alert(BaseModel):
    """Алерт, созданный правилом обнаружения для конкретного события."""

    alert_id: UUID = Field(default_factory=uuid4)
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    event_id: UUID
    timestamp: datetime
