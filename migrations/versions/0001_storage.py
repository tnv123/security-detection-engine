"""Создаёт таблицы событий и алертов."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0001_storage"
down_revision = None
branch_labels = None
depends_on = None


def _alert_columns() -> list[sa.Column]:
    return [
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("rule_name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    ]


def upgrade() -> None:
    """Создаёт таблицы и индексы."""
    op.create_table(
        "security_events",
        sa.Column("event_id", UUID(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("host", sa.String(), nullable=True),
        sa.Column("data", JSONB(), nullable=False),
    )
    op.create_index(
        "ix_events_timestamp_id", "security_events", ["timestamp", "event_id"]
    )
    op.create_index(
        "ix_events_source_type_time",
        "security_events",
        ["source", "event_type", "timestamp"],
    )
    op.create_table(
        "detection_alerts",
        sa.Column("alert_id", UUID(), primary_key=True),
        *_alert_columns(),
        sa.Column(
            "event_id",
            UUID(),
            sa.ForeignKey("security_events.event_id"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_alerts_timestamp_id", "detection_alerts", ["timestamp", "alert_id"]
    )
    op.create_index("ix_detection_alerts_event_id", "detection_alerts", ["event_id"])
    op.create_table(
        "correlation_alerts",
        sa.Column("correlation_id", UUID(), primary_key=True),
        *_alert_columns(),
        sa.Column("start_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("group_values", JSONB(), nullable=False),
        sa.CheckConstraint(
            "start_timestamp <= end_timestamp", name="ck_correlation_range"
        ),
        sa.CheckConstraint(
            "timestamp = end_timestamp", name="ck_correlation_timestamp"
        ),
    )
    op.create_index(
        "ix_correlations_timestamp_id",
        "correlation_alerts",
        ["timestamp", "correlation_id"],
    )
    op.create_table(
        "correlation_events",
        sa.Column(
            "correlation_id",
            UUID(),
            sa.ForeignKey("correlation_alerts.correlation_id"),
            primary_key=True,
        ),
        sa.Column("position", sa.Integer(), primary_key=True),
        sa.Column(
            "event_id",
            UUID(),
            sa.ForeignKey("security_events.event_id"),
            nullable=False,
        ),
        sa.CheckConstraint("position >= 0", name="ck_event_position"),
    )
    op.create_index(
        "ix_correlation_events_event_id", "correlation_events", ["event_id"]
    )


def downgrade() -> None:
    """Удаляет таблицы в порядке зависимостей."""
    op.drop_table("correlation_events")
    op.drop_table("correlation_alerts")
    op.drop_table("detection_alerts")
    op.drop_table("security_events")
