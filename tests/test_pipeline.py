from datetime import UTC, datetime
from pathlib import Path

import pytest

from security_detection_engine.analyzer import analyze_ssh_log
from security_detection_engine.correlation import (
    CorrelationEngine,
    load_correlation_rules_from_directory,
)
from security_detection_engine.detection import (
    DetectionEngine,
    load_rules_from_directory,
)
from security_detection_engine.models import EventSource, SecurityEvent
from security_detection_engine.pipeline import Pipeline

RULES = Path(__file__).resolve().parents[1] / "src/security_detection_engine/rules"


@pytest.fixture
def pipeline() -> Pipeline:
    return Pipeline(
        DetectionEngine(load_rules_from_directory(RULES)),
        CorrelationEngine(load_correlation_rules_from_directory(RULES / "correlation")),
    )


def ssh_event(outcome: str, second: int) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime(2024, 11, 16, 10, 0, second, tzinfo=UTC),
        source=EventSource.LINUX,
        event_type=f"ssh_authentication_{outcome}",
        data={"authentication_method": "password", "source_ip": "192.0.2.1"},
    )


def test_empty_input(pipeline):
    assert pipeline.process([]).model_dump() == {
        "event_count": 0,
        "alerts": [],
        "correlation_alerts": [],
        "alert_count": 0,
        "correlation_alert_count": 0,
    }


@pytest.mark.parametrize(
    ("outcome", "expected_alerts"), [("success", 0), ("failed", 1)]
)
def test_single_event(pipeline, outcome, expected_alerts):
    event = ssh_event(outcome, 0)
    result = pipeline.process([event])

    assert result.event_count == 1
    assert result.alert_count == expected_alerts
    assert [alert.event_id for alert in result.alerts] == [
        event.event_id
    ] * expected_alerts
    assert result.correlation_alert_count == 0


def test_ssh_analyzer_generator_feeds_both_engines(pipeline, tmp_path):
    log = tmp_path / "auth.log"
    outcomes = ["Failed", "Failed", "Failed", "Accepted"]
    log.write_text(
        "\n".join(
            f"Nov 16 10:00:0{i} server sshd[100]: {outcome} password for root "
            "from 192.0.2.1 port 54321 ssh2"
            for i, outcome in enumerate(outcomes)
        ),
        encoding="utf-8",
    )
    events = analyze_ssh_log(log, year=2024, tz=UTC).events
    snapshot = [event.model_copy(deep=True) for event in events]
    result = pipeline.process(event for event in reversed(events))

    assert events == snapshot
    assert result.event_count == 4
    assert result.alert_count == 3
    assert [a.event_id for a in result.alerts] == [e.event_id for e in events[2::-1]]
    assert result.correlation_alert_count == 1
    assert result.correlation_alerts[0].rule_id == "CORR-SSH-001"
    assert result.correlation_alerts[0].event_ids == [e.event_id for e in events]


def test_calls_have_independent_sequences_and_result_lists(pipeline):
    failures = [ssh_event("failed", second) for second in range(3)]
    success = ssh_event("success", 3)

    first = pipeline.process(failures)
    second = pipeline.process([success])
    third = pipeline.process([*failures, success])

    assert [first.event_count, second.event_count, third.event_count] == [3, 1, 4]
    assert [first.alert_count, second.alert_count, third.alert_count] == [3, 0, 3]
    assert first.correlation_alerts == second.correlation_alerts == []
    assert third.correlation_alert_count == 1
    third.alerts.clear()
    assert first.alert_count == 3
