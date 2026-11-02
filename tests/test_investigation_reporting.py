import csv

from scapy.all import Ether, IP, TCP

from analyzer.packet_parser import parse_packet
from database.connection import initialize_database
from investigations.case_manager import InvestigationManager
from reports.csv_export import CSVExporter
from reports.pdf_report import PDFReport


def test_packet_protocol_tree_exposes_decoded_fields_and_raw_bytes() -> None:
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=443, flags="S")
    packet.time = 1_700_000_000.125

    record = parse_packet(packet, 42)

    assert record.packet_number == 42
    assert record.timestamp == "2023-11-14T22:13:20.125000+00:00"
    assert record.protocol_tree[0]["name"] == "Frame"
    layers = {layer["name"]: layer["fields"] for layer in record.protocol_tree}
    assert layers["TCP"]["dport"] == 443
    assert record.raw_bytes == bytes(packet)
    assert "0000:" in record.hex_dump


def test_investigation_events_persist_and_timeline_sorts_by_time(tmp_path) -> None:
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    manager = InvestigationManager(connection)
    investigation_id = manager.create_investigation("Test case", "Packet investigation")
    manager.add_event(
        investigation_id,
        event_type="note",
        summary="Later note",
        timestamp="2024-01-01T02:00:00+01:00",
    )
    manager.add_event(
        investigation_id,
        event_type="alert",
        summary="Earlier alert",
        timestamp="2024-01-01T00:30:00+00:00",
        source_reference="alert:7",
        metadata={"severity": "high"},
    )

    events = manager.get_timeline(investigation_id)

    assert [event.summary for event in events[:2]] == ["Earlier alert", "Later note"]
    assert events[0].metadata == {"severity": "high"}
    assert manager.get_investigation(investigation_id)["status"] == "open"

    manager.set_status(investigation_id, "closed")
    assert manager.get_investigation(investigation_id)["status"] == "closed"
    assert manager.get_timeline(investigation_id)[-1].event_type == "status"
    connection.close()


def test_packet_csv_and_investigation_pdf_are_real_exports(tmp_path) -> None:
    packet = parse_packet(
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=443),
        1,
    )
    csv_path = tmp_path / "packets.csv"
    CSVExporter.export_packets(str(csv_path), [packet])
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["packet_number"] == "1"
    assert rows[0]["destination_port"] == "443"

    pdf_path = tmp_path / "investigation.pdf"
    PDFReport(str(pdf_path)).generate_investigation(
        "Investigation report",
        {
            "id": 3,
            "status": "open",
            "description": "Review observed traffic",
            "analyst_notes": "",
        },
        [],
    )
    assert pdf_path.read_bytes().startswith(b"%PDF-")
