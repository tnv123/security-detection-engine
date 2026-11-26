"""Запрещает повтор одного события внутри корреляции."""

from alembic import op

revision = "0002_unique_events"
down_revision = "0001_storage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_correlation_event", "correlation_events", ["correlation_id", "event_id"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_correlation_event", "correlation_events", type_="unique")
