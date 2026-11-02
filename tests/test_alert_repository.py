import json

import pytest
from scapy.all import Ether, IP, TCP

from analyzer.packet_parser import parse_packet
from database.alert_repository import AlertRepository
from database.connection import initialize_database
from database.packet_repository import PacketRepository
from detection.detection_engine import DetectionEngine


def test_generated_alerts_persist_with_packet_evidence_and_filtering(tmp_path):
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    packets = PacketRepository(connection)
    session_id = packets.create_session(
        source_type="pcap",
        source_path="scan.pcap",
        status="completed",
    )
    records = [
        parse_packet(
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=40000 + port, dport=port, flags="S"),
            port,
        )
        for port in range(1, 16)
    ]
    packets.store_packets(session_id, records)

    generated = DetectionEngine().generate_alerts(iter(records))
    repository = AlertRepository(connection)
    inserted_ids = repository.persist_generated(session_id, generated)

    assert len(inserted_ids) == len(generated)
    alerts = repository.list_alerts(
        severity="high",
        status="new",
        source="192.0.2",
    )
    alert = next(row for row in alerts if row["rule_id"] == "PORT_SCAN")
    assert alert["capture_session_id"] == session_id
    assert alert["rule_id"] == "PORT_SCAN"
    assert json.loads(alert["supporting_packets"]) == [
        record.record_id for record in records
    ]
    assert repository.persist_generated(session_id, generated) == []
    connection.close()


def test_alert_status_updates_and_rejects_unknown_status(tmp_path):
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    repository = AlertRepository(connection)
    session_id = PacketRepository(connection).create_session(
        source_type="pcap",
        source_path="empty.pcap",
        status="completed",
    )
    alert_id = repository.persist_generated(
        session_id,
        [{
            "rule_id": "TEST",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "severity": "medium",
            "title": "Synthetic test finding",
            "description": "Test-only evidence",
            "source_address": "192.0.2.1",
            "destination_address": "198.51.100.1",
            "supporting_packets": [],
            "confidence": 0.5,
        }],
    )[0]

    assert repository.update_status(alert_id, "acknowledged", "Reviewed by test")
    row = repository.list_alerts(status="acknowledged")[0]
    assert row["analyst_notes"] == "Reviewed by test"
    assert repository.update_status(alert_id, "resolved")
    assert repository.list_alerts(status="resolved")
    with pytest.raises(ValueError, match="Unsupported alert status"):
        repository.update_status(alert_id, "closed")
    connection.close()
