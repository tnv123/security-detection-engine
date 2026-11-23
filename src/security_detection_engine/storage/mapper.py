from security_detection_engine.correlation.models import CorrelationAlert
from security_detection_engine.models import SecurityEvent
from security_detection_engine.storage.models import CorrelationAlertRow, EventRow


def event_to_row(event: SecurityEvent) -> EventRow:
    """Преобразует событие, сериализуя data в JSON-совместимые значения."""
    values = event.model_dump()
    values["data"] = event.model_dump(mode="json")["data"]
    return EventRow(**values)


def correlation_from_row(row: CorrelationAlertRow) -> CorrelationAlert:
    """Восстанавливает алерт с исходным порядком UUID событий."""
    return CorrelationAlert(
        correlation_id=row.correlation_id,
        rule_id=row.rule_id,
        rule_name=row.rule_name,
        description=row.description,
        severity=row.severity,
        timestamp=row.timestamp,
        start_timestamp=row.start_timestamp,
        end_timestamp=row.end_timestamp,
        group_values=row.group_values,
        event_ids=[link.event_id for link in row.events],
    )
