from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from xml.etree.ElementTree import Element

from security_detection_engine.windows.models import WindowsEventRecord

SUPPORTED_EVENT_IDS = (4624, 4625)


class ParseStatus(StrEnum):
    """Результат разбора XML-события."""

    PARSED = "parsed"
    UNSUPPORTED = "unsupported"
    INVALID = "invalid"


@dataclass(frozen=True)
class ParseResult:
    """Результат разбора события: статус и запись при успешном разборе."""

    status: ParseStatus
    record: WindowsEventRecord | None = None


def parse_event(element: Element) -> ParseResult:
    """Разбирает XML-элемент Event в WindowsEventRecord.

    Поддерживаются только Event ID 4624 и 4625; события с другими
    идентификаторами возвращают UNSUPPORTED, повреждённые — INVALID.
    """
    system = _find_child(element, "System")
    if system is None:
        return ParseResult(ParseStatus.INVALID)

    event_id = _parse_event_id(system)
    if event_id is None:
        return ParseResult(ParseStatus.INVALID)
    if event_id not in SUPPORTED_EVENT_IDS:
        return ParseResult(ParseStatus.UNSUPPORTED)

    timestamp = _parse_timestamp(system)
    if timestamp is None:
        return ParseResult(ParseStatus.INVALID)

    computer = _find_child(system, "Computer")
    provider = _find_child(system, "Provider")
    event_data_element = _find_child(element, "EventData")

    try:
        record = WindowsEventRecord(
            event_id=event_id,
            timestamp=timestamp,
            computer=computer.text.strip()
            if computer is not None and computer.text
            else None,
            provider=provider.get("Name") if provider is not None else None,
            event_data=_parse_event_data(event_data_element),
        )
    except ValueError:
        return ParseResult(ParseStatus.INVALID)
    return ParseResult(ParseStatus.PARSED, record=record)


def _parse_event_id(system: Element) -> int | None:
    element = _find_child(system, "EventID")
    if element is None or element.text is None:
        return None
    try:
        return int(element.text.strip())
    except ValueError:
        return None


def _parse_timestamp(system: Element) -> datetime | None:
    element = _find_child(system, "TimeCreated")
    if element is None:
        return None
    raw = element.get("SystemTime")
    if not raw:
        return None
    try:
        timestamp = datetime.fromisoformat(raw)
    except ValueError:
        return None
    # События без часового пояса недостоверны — отклоняем их
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        return None
    return timestamp


def _parse_event_data(element: Element | None) -> dict[str, str]:
    data = {}
    if element is not None:
        for item in element:
            if _local_name(item.tag) == "Data" and item.get("Name"):
                name = item.attrib["Name"]
                if name in data:
                    raise ValueError("Повторное имя EventData")
                data[name] = item.text or ""
    return data


def _find_child(element: Element, name: str) -> Element | None:
    for child in element:
        if _local_name(child.tag) == name:
            return child
    return None


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
