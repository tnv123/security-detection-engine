from pydantic import BaseModel, Field, computed_field

from security_detection_engine.correlation.models import CorrelationAlert
from security_detection_engine.detection.models import Alert


class PipelineResult(BaseModel):
    """Сводный результат анализа одной партии событий."""

    event_count: int = Field(ge=0)
    alerts: list[Alert]
    correlation_alerts: list[CorrelationAlert]

    @computed_field
    @property
    def alert_count(self) -> int:
        """Количество алертов обнаружения."""
        return len(self.alerts)

    @computed_field
    @property
    def correlation_alert_count(self) -> int:
        """Количество корреляционных алертов."""
        return len(self.correlation_alerts)
