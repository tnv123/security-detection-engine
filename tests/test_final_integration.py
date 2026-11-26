from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier, Event
from uuid import uuid4

import pytest
from alembic import command
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import wrpcap
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_api_postgresql import client as client
from test_ssh_analyzer import ACCEPTED_LINE, FAILED_LINE
from test_storage_postgresql import batch as batch
from test_storage_postgresql import database as database
from test_windows_analyzer import event_xml, write_log

from security_detection_engine.analyzer import analyze_ssh_log
from security_detection_engine.models import SecurityEvent
from security_detection_engine.network import analyze_pcap
from security_detection_engine.storage import PipelineResultStore, transaction
from security_detection_engine.windows import analyze_windows_log

pytestmark = pytest.mark.postgresql


@pytest.fixture
def source_events(tmp_path):
    ssh_path = tmp_path / "auth.log"
    ssh_path.write_text(
        "\n".join(
            [FAILED_LINE.replace("10:15:32", f"10:15:3{i}") for i in range(3)]
            + [
                ACCEPTED_LINE,
                "unsupported",
                "Nov 16 10:15:32 server sshd[1234]: Failed",
            ]
        )
    )
    ssh = analyze_ssh_log(ssh_path, year=2024, tz=UTC)
    assert (len(ssh.events), ssh.invalid_lines, ssh.unsupported_lines) == (4, 1, 1)
    xml_path = write_log(
        tmp_path / "events.xml",
        event_xml("4624"),
        event_xml("4625", data='<Data Name="IpAddress">192.0.2.3</Data>'),
        event_xml("9999"),
        event_xml("4624", timestamp="invalid"),
    )
    windows = analyze_windows_log(xml_path)
    assert (
        windows.total_events,
        windows.parsed_events,
        windows.invalid_events,
        windows.unsupported_events,
    ) == (4, 2, 1, 1)
    assert [e.event_type for e in windows.events] == [
        "windows_logon_success",
        "windows_logon_failed",
    ]
    assert all(e.host == "DC-01" and e.timestamp.tzinfo for e in windows.events)
    assert windows.events[1].data["event_id"] == 4625
    assert windows.events[1].data["IpAddress"] == "192.0.2.3"
    packets = [
        IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=111, dport=22, flags="S"),
        IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=222, dport=53),
        IP(src="192.0.2.1", dst="192.0.2.2") / ICMP(),
        IP() / IP() / TCP(),
        IPv6() / TCP(),
    ]
    for i, packet in enumerate(packets):
        packet.time = 1700000000 + i
    pcap = tmp_path / "packets.pcap"
    wrpcap(str(pcap), packets)
    network = analyze_pcap(pcap)
    assert (
        network.total_packets,
        network.parsed_packets,
        network.invalid_packets,
        network.unsupported_packets,
    ) == (5, 3, 0, 2)
    for event, packet, protocol in zip(network.events, packets, ["tcp", "udp", "icmp"]):
        assert event.data["source_ip"] == "192.0.2.1"
        assert event.data["destination_ip"] == "192.0.2.2"
        assert event.data["protocol"] == protocol
        assert event.data["packet_size"] == len(packet)
        assert event.timestamp == datetime.fromtimestamp(float(packet.time), UTC)
    assert network.events[0].data["source_port"] == 111
    assert network.events[0].data["destination_port"] == 22
    assert network.events[0].data["tcp_flags"] == "S"
    assert network.events[1].data["destination_port"] == 53
    assert network.events[2].data["source_port"] is None
    return {"linux": ssh.events, "windows": windows.events, "network": network.events}


@pytest.mark.parametrize("source", ["linux", "windows", "network", "mixed"])
@pytest.mark.parametrize("entry", ["direct", "http"])
def test_source_end_to_end(client, database, source_events, source, entry):
    events = (
        sum(source_events.values(), []) if source == "mixed" else source_events[source]
    )
    pipeline = client.app.state.pipeline
    result = pipeline.process(iter(events))
    assert result.event_count == len(events)
    assert result.alert_count == (3 if source in ("linux", "mixed") else 0)
    assert result.correlation_alert_count == (1 if source in ("linux", "mixed") else 0)
    if result.correlation_alerts:
        assert result.correlation_alerts[0].event_ids == [
            e.event_id for e in source_events["linux"]
        ]
    if entry == "direct":
        with transaction(database[0]) as session:
            PipelineResultStore(session).save(events, result)
    else:
        response = client.post(
            "/analyze", json={"events": [e.model_dump(mode="json") for e in events]}
        )
        assert response.status_code == 200
        assert response.json()["alert_count"] == result.alert_count
    for event in events:
        response = client.get(f"/events/{event.event_id}")
        assert response.status_code == 200
        assert SecurityEvent.model_validate(response.json()) == event
    all_events = client.get("/events").json()
    assert len(all_events) == len(events)
    assert len(client.get("/alerts").json()) == result.alert_count
    correlations = client.get("/correlation-alerts").json()
    if correlations:
        assert correlations[0]["event_ids"] == [
            str(e.event_id) for e in source_events["linux"]
        ]
    for kind in set(e.source for e in events):
        assert len(client.get("/events", params={"source": kind}).json()) == sum(
            e.source == kind for e in events
        )
    first = events[0]
    filtered = client.get(
        "/events",
        params={
            "event_type": first.event_type,
            "start_time": first.timestamp.isoformat(),
            "end_time": first.timestamp.isoformat(),
        },
    ).json()
    assert str(first.event_id) in [item["event_id"] for item in filtered]
    assert len(client.get("/events", params={"limit": 1, "offset": 1}).json()) == 1


def test_concurrent_transactions(client, batch, monkeypatch):
    events, _ = batch
    original = PipelineResultStore.save
    sessions = []
    barrier = Barrier(2, timeout=15)

    def synchronized(store, party, result):
        sessions.append(store.session)
        barrier.wait()
        return original(store, party, result)

    monkeypatch.setattr(PipelineResultStore, "save", synchronized)

    def post(party):
        return client.post(
            "/analyze", json={"events": [e.model_dump(mode="json") for e in party]}
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        independent = [
            [e.model_copy(update={"event_id": uuid4()}) for e in events]
            for _ in range(2)
        ]
        responses = list(pool.map(post, independent, timeout=25))
        assert [r.status_code for r in responses] == [200, 200]
        for response, party in zip(responses, independent):
            assert response.json()["correlation_alerts"][0]["event_ids"] == [
                str(event.event_id) for event in party
            ]
        assert len({id(s) for s in sessions}) == 2
        assert len(client.get("/events").json()) == 8
        assert len(client.get("/alerts").json()) == 6
        assert len(client.get("/correlation-alerts").json()) == 2
        shared = events[0].model_copy(update={"event_id": uuid4()})
        parties = [
            [e.model_copy(update={"event_id": uuid4()}), shared] for e in events[1:3]
        ]
        responses = list(pool.map(post, parties, timeout=25))
        assert sorted(r.status_code for r in responses) == [200, 409]
        assert len(client.get("/events").json()) == 10
        assert len(client.get("/alerts").json()) == 8
        winner = next(i for i, r in enumerate(responses) if r.status_code == 200)
        assert (
            client.get(f"/events/{parties[1 - winner][0].event_id}").status_code == 404
        )
        good = [e.model_copy(update={"event_id": uuid4()}) for e in events]
        invalid = [good[0].model_copy(update={"event_id": uuid4()})]
        invalid *= 2
        responses = list(pool.map(post, [good, invalid], timeout=25))
        assert [r.status_code for r in responses] == [200, 409]
        assert len(client.get("/events").json()) == 14
    monkeypatch.setattr(PipelineResultStore, "save", original)
    assert post([events[3].model_copy(update={"event_id": uuid4()})]).status_code == 200


def test_uncommitted_writes_invisible(client, batch, monkeypatch):
    original = PipelineResultStore.save
    flushed, release = Event(), Event()

    def pause(store, events, result):
        original(store, events, result)
        flushed.set()
        assert release.wait(15)

    monkeypatch.setattr(PipelineResultStore, "save", pause)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(
            client.post,
            "/analyze",
            json={"events": [e.model_dump(mode="json") for e in batch[0]]},
        )
        try:
            assert flushed.wait(15)
            assert client.get("/events").json() == []
            assert client.get("/alerts").json() == []
            assert client.get("/correlation-alerts").json() == []
        finally:
            release.set()
        assert pending.result(20).status_code == 200
    assert len(client.get("/events").json()) == 4


def test_migration_preserves_data_and_unique_links(database, batch):
    from security_detection_engine.storage import CorrelationAlertRepository

    factory, config = database
    events, result = batch
    command.downgrade(config, "0001_storage")
    with transaction(factory) as session:
        PipelineResultStore(session).save(events, result)
    command.upgrade(config, "head")
    command.check(config)
    alert = result.correlation_alerts[0]
    with transaction(factory) as session:
        restored = CorrelationAlertRepository(session).get(alert.correlation_id)
        assert restored == alert
    with pytest.raises(IntegrityError) as error, transaction(factory) as session:
        session.execute(
            text(
                "INSERT INTO correlation_events(correlation_id,position,event_id) "
                "VALUES (:correlation,99,:event)"
            ),
            {"correlation": alert.correlation_id, "event": events[0].event_id},
        )
    assert error.value.orig.diag.constraint_name == "uq_correlation_event"
