from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Базовый класс таблиц хранения."""


class EventRow(Base):
    """Нормализованное событие."""

    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_events_timestamp_id", "timestamp", "event_id"),
        Index("ix_events_source_type_time", "source", "event_type", "timestamp"),
    )

    event_id: Mapped[UUID] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String)
    event_type: Mapped[str] = mapped_column(String)
    severity: Mapped[str | None] = mapped_column(String)
    host: Mapped[str | None] = mapped_column(String)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)


class AlertRow(Base):
    """Алерт обнаружения с внешним ключом события."""

    __tablename__ = "detection_alerts"
    __table_args__ = (Index("ix_alerts_timestamp_id", "timestamp", "alert_id"),)

    alert_id: Mapped[UUID] = mapped_column(primary_key=True)
    rule_id: Mapped[str]
    rule_name: Mapped[str]
    description: Mapped[str]
    severity: Mapped[str]
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_id: Mapped[UUID] = mapped_column(
        ForeignKey("security_events.event_id"), index=True
    )


class CorrelationAlertRow(Base):
    """Корреляционный алерт и упорядоченные связи с событиями."""

    __tablename__ = "correlation_alerts"
    __table_args__ = (
        Index("ix_correlations_timestamp_id", "timestamp", "correlation_id"),
        CheckConstraint(
            "start_timestamp <= end_timestamp", name="ck_correlation_range"
        ),
        CheckConstraint("timestamp = end_timestamp", name="ck_correlation_timestamp"),
    )

    correlation_id: Mapped[UUID] = mapped_column(primary_key=True)
    rule_id: Mapped[str]
    rule_name: Mapped[str]
    description: Mapped[str]
    severity: Mapped[str]
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    start_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    end_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    group_values: Mapped[dict[str, Any]] = mapped_column(JSONB)
    events: Mapped[list["CorrelationEventRow"]] = relationship(
        cascade="all, delete-orphan",
        order_by="CorrelationEventRow.position",
        lazy="selectin",
    )


class CorrelationEventRow(Base):
    """Позиция события в корреляционной последовательности."""

    __tablename__ = "correlation_events"
    __table_args__ = (
        CheckConstraint("position >= 0", name="ck_event_position"),
        UniqueConstraint("correlation_id", "event_id", name="uq_correlation_event"),
    )

    correlation_id: Mapped[UUID] = mapped_column(
        ForeignKey("correlation_alerts.correlation_id"), primary_key=True
    )
    position: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[UUID] = mapped_column(
        ForeignKey("security_events.event_id"), index=True
    )
