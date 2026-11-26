from security_detection_engine.models import EventSource, SecurityEvent, Severity
from security_detection_engine.windows.models import WindowsEventRecord


def normalize_windows_record(record: WindowsEventRecord) -> SecurityEvent:
    """Преобразует запись события Windows Event Log в SecurityEvent."""
    if record.event_id == 4624:
        event_type = "windows_logon_success"
        severity = None
    else:
        event_type = "windows_logon_failed"
        severity = Severity.LOW

    return SecurityEvent(
        timestamp=record.timestamp,
        source=EventSource.WINDOWS,
        event_type=event_type,
        severity=severity,
        host=record.computer,
        data={
            **record.event_data,
            "event_id": record.event_id,
            "provider": record.provider,
        },
    )
