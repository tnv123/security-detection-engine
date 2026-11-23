from collections.abc import Iterable
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_detection_engine.correlation.models import CorrelationAlert
from security_detection_engine.detection.models import Alert
from security_detection_engine.models import EventSource, SecurityEvent
from security_detection_engine.storage.mapper import correlation_from_row, event_to_row
from security_detection_engine.storage.models import (
    AlertRow,
    CorrelationAlertRow,
    CorrelationEventRow,
    EventRow,
)


def _check_pagination(limit: int, offset: int) -> None:
    if limit <= 0 or offset < 0:
        raise ValueError("limit должен быть > 0, offset должен быть >= 0")


def _check_timestamp(value: datetime | None) -> None:
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise ValueError("Временная граница должна содержать часовой пояс")


class EventRepository:
    """Хранение событий в транзакции вызывающего кода."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def save(self, event: SecurityEvent) -> None:
        """Добавляет событие; повторный UUID вызывает IntegrityError."""
        self.save_many([event])

    def save_many(self, events: Iterable[SecurityEvent]) -> None:
        """Добавляет партию событий без commit."""
        self.session.add_all(event_to_row(event) for event in events)
        self.session.flush()

    def get(self, event_id: UUID) -> SecurityEvent | None:
        """Получает событие по UUID."""
        row = self.session.get(EventRow, event_id)
        return SecurityEvent.model_validate(row, from_attributes=True) if row else None

    def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        source: EventSource | None = None,
        event_type: str | None = None,
        start_timestamp: datetime | None = None,
        end_timestamp: datetime | None = None,
    ) -> list[SecurityEvent]:
        """Возвращает события по времени и UUID с включительными границами."""
        _check_pagination(limit, offset)
        _check_timestamp(start_timestamp)
        _check_timestamp(end_timestamp)
        if start_timestamp and end_timestamp and start_timestamp > end_timestamp:
            raise ValueError("Начало диапазона должно быть <= конца")
        query = select(EventRow)
        if source is not None:
            query = query.where(EventRow.source == source)
        if event_type is not None:
            query = query.where(EventRow.event_type == event_type)
        if start_timestamp is not None:
            query = query.where(EventRow.timestamp >= start_timestamp)
        if end_timestamp is not None:
            query = query.where(EventRow.timestamp <= end_timestamp)
        rows = self.session.scalars(
            query.order_by(EventRow.timestamp, EventRow.event_id)
            .limit(limit)
            .offset(offset)
        )
        return [SecurityEvent.model_validate(row, from_attributes=True) for row in rows]


class AlertRepository:
    """Хранение обычных алертов."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def save(self, alert: Alert) -> None:
        """Добавляет алерт без commit; повторный UUID вызывает IntegrityError."""
        _check_timestamp(alert.timestamp)
        self.session.add(AlertRow(**alert.model_dump()))
        self.session.flush()

    def get(self, alert_id: UUID) -> Alert | None:
        """Получает алерт по UUID."""
        row = self.session.get(AlertRow, alert_id)
        return Alert.model_validate(row, from_attributes=True) if row else None

    def list(self, *, limit: int = 100, offset: int = 0) -> list[Alert]:
        """Возвращает страницу алертов по времени и UUID."""
        _check_pagination(limit, offset)
        rows = self.session.scalars(
            select(AlertRow)
            .order_by(AlertRow.timestamp, AlertRow.alert_id)
            .limit(limit)
            .offset(offset)
        )
        return [Alert.model_validate(row, from_attributes=True) for row in rows]


class CorrelationAlertRepository:
    """Хранение корреляционных алертов и позиций связанных событий."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def save(self, alert: CorrelationAlert) -> None:
        """Добавляет алерт со связями без commit."""
        values = alert.model_dump(exclude={"event_ids"})
        values["group_values"] = alert.model_dump(mode="json")["group_values"]
        row = CorrelationAlertRow(**values)
        row.events = [
            CorrelationEventRow(position=position, event_id=event_id)
            for position, event_id in enumerate(alert.event_ids)
        ]
        self.session.add(row)
        self.session.flush()

    def get(self, correlation_id: UUID) -> CorrelationAlert | None:
        """Получает алерт по UUID с восстановленным порядком событий."""
        row = self.session.get(CorrelationAlertRow, correlation_id)
        return correlation_from_row(row) if row else None

    def list(self, *, limit: int = 100, offset: int = 0) -> list[CorrelationAlert]:
        """Возвращает страницу алертов по времени и UUID."""
        _check_pagination(limit, offset)
        rows = self.session.scalars(
            select(CorrelationAlertRow)
            .order_by(CorrelationAlertRow.timestamp, CorrelationAlertRow.correlation_id)
            .limit(limit)
            .offset(offset)
        )
        return [correlation_from_row(row) for row in rows]
