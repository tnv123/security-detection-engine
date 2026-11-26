import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from scapy.layers.inet import ICMP, IP, TCP
from sqlalchemy import text
from test_ssh_analyzer import FAILED_LINE
from test_storage_postgresql import batch as batch
from test_storage_postgresql import database as database
from test_windows_analyzer import event_xml, write_log

from security_detection_engine.analyzer import analyze_ssh_log
from security_detection_engine.api.app import create_app
from security_detection_engine.api.body import RequestBodyLimit
from security_detection_engine.config import Settings
from security_detection_engine.detection.loader import (
    RuleLoadError,
    load_rules_from_directory,
)
from security_detection_engine.detection.matcher import match_condition
from security_detection_engine.detection.models import Condition
from security_detection_engine.models import SecurityEvent
from security_detection_engine.network.parser import parse_packet
from security_detection_engine.storage import (
    EventRepository,
    PipelineResultStore,
    transaction,
)
from security_detection_engine.storage.mapper import event_to_row
from security_detection_engine.windows import analyze_windows_log


@pytest.mark.parametrize("name", ["event_id", "provider", "same"])
def test_windows_conflicts_resume(name, tmp_path):
    field = f'<Data Name="{name}">text</Data>'
    good = event_xml("4624").replace("DC-01", " ")
    result = analyze_windows_log(
        write_log(
            tmp_path / "log.xml",
            good,
            event_xml("4625", data=field * (2 if name == "same" else 1)),
            good,
        )
    )
    assert (
        result.total_events,
        result.parsed_events,
        result.invalid_events,
        result.unsupported_events,
    ) == (3, 2, 1, 0)
    assert all(e.host is None for e in result.events)


@pytest.mark.parametrize("number", ["1234", "54321"])
def test_ssh_bad_number_and_ipv6(number, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "\n".join(
            [
                FAILED_LINE.replace("192.168.1.10", "2001:0db8:0:0:0:0:0:1"),
                FAILED_LINE.replace(number, "9" * 5000),
                FAILED_LINE.replace("192.168.1.10", "2001:db8::1"),
            ]
        )
    )
    result = analyze_ssh_log(log, year=2024, tz=UTC)
    assert [e.data["source_ip"] for e in result.events] == ["2001:db8::1"] * 2
    assert (result.invalid_lines, result.unsupported_lines) == (1, 0)


def test_outer_transport_only():
    assert parse_packet(IP() / IP() / TCP()) is None
    assert parse_packet(IP(flags="MF") / TCP()) is None
    assert parse_packet(IP(frag=1) / TCP()) is None
    record = parse_packet(IP() / ICMP() / IP() / TCP())
    assert record.protocol == "icmp" and record.source_port is None


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_at_input_and_after_mutation(number):
    event = SecurityEvent(
        timestamp=datetime.now(UTC),
        source="linux",
        event_type="test",
        data={"ok": [None, False, 1, 1.5, "s", uuid4(), datetime.now(UTC)]},
    )
    event.data["nested"] = [{"x": number}]
    with pytest.raises(ValueError):
        event_to_row(event)
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(event.model_dump())
    with pytest.raises(ValidationError):
        Condition(field="x", operator="equals", value=number)


@pytest.mark.parametrize(
    ("left", "right", "equal"),
    [
        (True, 1, False),
        (0, False, False),
        (1, 1.0, True),
        ("1", 1, False),
        ([True], [1], False),
    ],
)
def test_rule_equality(left, right, equal):
    assert (
        match_condition(
            {"x": left}, Condition(field="x", operator="equals", value=right)
        )
        is equal
    )


def test_duplicate_disabled_rules(tmp_path):
    rule = "rule_id: example\nname: x\ndescription: x\n"
    rule += "severity: low\nevent_type: x\nenabled: false"
    for name in ["a.yaml", "b.yaml"]:
        (tmp_path / name).write_text(rule)
    with pytest.raises(RuleLoadError):
        load_rules_from_directory(tmp_path)


@pytest.mark.parametrize(
    ("chunks", "headers", "status"),
    [
        ([b"12"], [], 200),
        ([b"12", b"34"], [], 200),
        ([b"123", b"45"], [], 413),
        ([], [(b"content-length", b"5")], 413),
        ([b"12345"], [(b"content-length", b"2")], 413),
        ([b"12", None], [], None),
        ([], [(b"content-encoding", b"gzip")], 415),
    ],
)
def test_asgi_limit(chunks, headers, status):
    messages = [
        {"type": "http.disconnect"}
        if chunk is None
        else {"type": "http.request", "body": chunk, "more_body": i + 1 < len(chunks)}
        for i, chunk in enumerate(chunks)
    ]
    recv = AsyncMock(side_effect=messages)
    send = AsyncMock()

    async def downstream(scope, receive, send):
        assert (await receive())["body"] == b"".join(chunks)

    app = AsyncMock(side_effect=downstream)
    scope = {
        "type": "http",
        "method": "POST",
        "headers": headers,
        "app": SimpleNamespace(
            state=SimpleNamespace(settings=Settings(max_request_body_bytes=4))
        ),
    }
    asyncio.run(RequestBodyLimit(app)(scope, recv, send))
    if status == 200:
        app.assert_awaited_once()
    else:
        app.assert_not_awaited()
        if status is not None:
            assert send.await_args_list[0].args[0]["status"] == status


@pytest.mark.postgresql
def test_rejected_http_batch_and_schema(database):
    factory, _ = database
    with TestClient(create_app(Settings(max_request_body_bytes=256))) as client:
        assert client.post("/analyze", content=b"x" * 257).status_code == 413
        raw = '{"events":[{"source":"linux","event_type":"x",'
        raw += '"timestamp":"2024-01-01T00:00:00Z","data":{"x":NaN}}]}'
        assert (
            client.post(
                "/analyze", content=raw, headers={"Content-Type": "application/json"}
            ).status_code
            == 422
        )
        with transaction(factory) as s:
            assert EventRepository(s).list() == []
        for revision in ["0001_storage", "unexpected"]:
            with transaction(factory) as s:
                s.execute(
                    text("UPDATE alembic_version SET version_num=:r"), {"r": revision}
                )
            assert client.get("/health/ready").status_code == 503
        with transaction(factory) as s:
            s.execute(text("DROP TABLE alembic_version"))
        assert client.get("/health/ready").status_code == 503
        assert client.get("/health").status_code == 200


@pytest.mark.postgresql
def test_mutated_correlation_rollback(database, batch):
    factory, _ = database
    events, result = batch
    alert = result.correlation_alerts[0]
    alert.event_ids[1] = alert.event_ids[0]
    with pytest.raises(ValidationError), transaction(factory) as session:
        PipelineResultStore(session).save(events, result)
    with transaction(factory) as session:
        assert EventRepository(session).list() == []


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_group_values_and_mutated_group(number, batch):
    from unittest.mock import Mock

    from security_detection_engine.correlation import CorrelationAlert
    from security_detection_engine.storage import CorrelationAlertRepository

    _, result = batch
    alert = result.correlation_alerts[0]
    alert.group_values["nested"] = [number]
    with pytest.raises(ValidationError):
        CorrelationAlert.model_validate(alert.model_dump())
    with pytest.raises(ValidationError):
        CorrelationAlertRepository(Mock()).save(alert)


@pytest.mark.postgresql
def test_json_numeric_round_trip(database, batch):
    factory, _ = database
    events, result = batch
    events[0].data["values"] = [None, False, 0, 1.5]
    with transaction(factory) as session:
        PipelineResultStore(session).save(events, result)
    with transaction(factory) as session:
        values = EventRepository(session).get(events[0].event_id).data["values"]
        assert values == [None, False, 0, 1.5]
        assert list(map(type, values)) == [type(None), bool, int, float]
