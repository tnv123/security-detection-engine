from typing import Self

from pydantic import AwareDatetime, BaseModel, Field, model_validator

from security_detection_engine.models import EventSource, SecurityEvent


class AnalyzeRequest(BaseModel):
    """Партия нормализованных событий для независимого анализа."""

    events: list[SecurityEvent] = Field(max_length=1000)


class Pagination(BaseModel):
    """Параметры ограниченной страницы результатов."""

    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class EventFilters(Pagination):
    """Фильтры событий с включительными временными границами."""

    source: EventSource | None = None
    event_type: str | None = None
    start_time: AwareDatetime | None = None
    end_time: AwareDatetime | None = None

    @model_validator(mode="after")
    def check_range(self) -> Self:
        """Проверяет порядок границ временного диапазона."""
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time должен быть <= end_time")
        return self
