import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, tzinfo
from enum import StrEnum

_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)

_AUTH_ATTEMPT = re.compile(
    r"^(?P<action>Failed|Accepted)\s+(?P<method>\S+)\s+for\s+"
    r"(?P<invalid>invalid user\s+)?(?P<username>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
    # Типичный хвост OpenSSH: "ssh2" либо "ssh2: ED25519 SHA256:..." и т.п.
    r"(?:\s+ssh\d(?::\s+(?:RSA|ED25519|ECDSA|DSA)\s+SHA256:\S+)?)?\s*$"
)


class ParseStatus(StrEnum):
    """Результат разбора строки лога."""

    PARSED = "parsed"
    UNSUPPORTED = "unsupported"
    INVALID = "invalid"


@dataclass(frozen=True)
class SshAuthRecord:
    """Структурированная запись SSH-аутентификации из строки лога."""

    timestamp: datetime
    hostname: str
    process_id: int
    success: bool
    authentication_method: str
    username: str
    source_ip: str
    source_port: int
    invalid_user: bool


@dataclass(frozen=True)
class ParseResult:
    """Результат разбора строки: статус и запись при успешном разборе."""

    status: ParseStatus
    record: SshAuthRecord | None = None
    raw: str = ""


def parse_ssh_auth_line(line: str, *, year: int, tz: tzinfo) -> ParseResult:
    """Разбирает строку лога sshd в SshAuthRecord.

    Syslog-метка времени не содержит года и часового пояса, поэтому они
    передаются явно параметрами year и tz.
    """
    prefix = _SYSLOG_PREFIX.match(line)
    if prefix is None:
        return ParseResult(ParseStatus.UNSUPPORTED, raw=line)

    message = prefix["message"]
    attempt = _AUTH_ATTEMPT.match(message)
    if attempt is None:
        if message.startswith(("Failed", "Accepted")):
            # Строка похожа на событие аутентификации, но структура нарушена
            return ParseResult(ParseStatus.INVALID, raw=line)
        return ParseResult(ParseStatus.UNSUPPORTED, raw=line)

    month = _MONTHS.get(prefix["month"])
    if month is None:
        return ParseResult(ParseStatus.INVALID, raw=line)

    try:
        address = ipaddress.ip_address(attempt["ip"])
        pid = int(prefix["pid"])
        port = int(attempt["port"])
    except ValueError:
        return ParseResult(ParseStatus.INVALID, raw=line)

    if not 1 <= port <= 65535:
        return ParseResult(ParseStatus.INVALID, raw=line)

    if pid < 1:
        return ParseResult(ParseStatus.INVALID, raw=line)

    try:
        timestamp = datetime(
            year,
            month,
            int(prefix["day"]),
            int(prefix["hour"]),
            int(prefix["minute"]),
            int(prefix["second"]),
            tzinfo=tz,
        )
    except ValueError:
        return ParseResult(ParseStatus.INVALID, raw=line)

    record = SshAuthRecord(
        timestamp=timestamp,
        hostname=prefix["host"],
        process_id=pid,
        success=attempt["action"] == "Accepted",
        authentication_method=attempt["method"],
        username=attempt["username"],
        source_ip=str(address),
        source_port=port,
        invalid_user=attempt["invalid"] is not None,
    )
    return ParseResult(ParseStatus.PARSED, record=record, raw=line)
