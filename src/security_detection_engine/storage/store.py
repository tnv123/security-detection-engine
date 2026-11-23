from collections.abc import Iterable

from sqlalchemy.orm import Session

from security_detection_engine.models import SecurityEvent
from security_detection_engine.pipeline import PipelineResult
from security_detection_engine.storage.repositories import (
    AlertRepository,
    CorrelationAlertRepository,
    EventRepository,
)


class PipelineResultStore:
    """Сохраняет партию внутри транзакции переданной Session.

    Вызывающий код открывает session.begin() и обрабатывает ошибки за его
    пределами. Внешние ключи проверяют наличие всех исходных событий.
    """

    def __init__(self, session: Session) -> None:
        self.session = session

    def save(self, events: Iterable[SecurityEvent], result: PipelineResult) -> None:
        """Сохраняет события и алерты, проверяя число событий партии."""
        batch = list(events)
        if len(batch) != result.event_count:
            raise ValueError("Размер партии не совпадает с PipelineResult.event_count")
        EventRepository(self.session).save_many(batch)
        for alert in result.alerts:
            AlertRepository(self.session).save(alert)
        for alert in result.correlation_alerts:
            CorrelationAlertRepository(self.session).save(alert)
