import threading
import json
import csv
import sqlite3

import pytest
from scapy.all import ARP, Ether, IP, TCP, UDP, wrpcap

from analyzer.filter_engine import evaluate_filter
from analyzer.packet_parser import parse_packet
from capture.pcap_reader import read_pcap_file
from capture.capture_manager import CaptureManager
from database.connection import initialize_database
from database.packet_repository import (
    PacketRepository,
    PacketStorageWorker,
    packet_record_from_row,
)
from reports.csv_export import CSVExporter


def _packet(source: str = "192.0.2.1", destination_port: int = 443):
    return (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=source, dst="198.51.100.2")
        / TCP(sport=12345, dport=destination_port, flags="S")
    )


def test_repository_persists_session_metadata_and_pages_packets(tmp_path):
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    repository = PacketRepository(connection)
    session_id = repository.create_session(
        source_type="pcap",
        source_path="sample.pcap",
        status="importing",
    )
    records = [parse_packet(_packet(), number) for number in range(1, 4)]
    repository.store_packets(session_id, records, source_path="sample.pcap")
    other_session_id = repository.create_session(
        source_type="pcap",
        source_path="other.pcap",
        status="importing",
    )
    repository.store_packets(
        other_session_id,
        [parse_packet(_packet(source="203.0.113.1"), 1)],
        source_path="other.pcap",
    )

    assert [record.session_id for record in records] == [session_id] * 3
    assert all(record.record_id is not None for record in records)
    page = repository.get_packet_page(session_id, limit=2)
    assert [row["packet_number"] for row in page] == [1, 2]
    assert page[0]["original_reference"] == "sample.pcap#packet=1"
    assert "ip" in json.loads(page[0]["details"])
    assert "tcp" in json.loads(page[0]["details"])
    assert len(repository.get_packet_page(other_session_id, limit=10)) == 1
    assert repository.get_session(session_id)["packet_count"] == 3
    assert repository.get_session(session_id)["byte_count"] == sum(
        record.packet_length for record in records
    )

    repository.finish_session(
        session_id,
        "completed",
        capture_stats={"malformed_packets": 1},
    )
    session = repository.get_session(session_id)
    assert session["status"] == "completed"
    assert '"malformed_packets": 1' in session["capture_stats"]
    connection.close()


def test_repository_filter_sql_matches_existing_filter_engine(tmp_path):
    packets = [
        parse_packet(_packet("192.0.2.1", 443), 1),
        parse_packet(
            Ether()
            / IP(src="192.0.2.2", dst="198.51.100.3")
            / TCP(sport=2345, dport=80, flags="A"),
            2,
        ),
        parse_packet(
            Ether()
            / IP(src="203.0.113.8", dst="198.51.100.4")
            / UDP(sport=5353, dport=53),
            3,
        ),
        parse_packet(Ether() / ARP(psrc="192.0.2.9", pdst="192.0.2.1"), 4),
    ]
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    repository = PacketRepository(connection)
    session_id = repository.create_session(
        source_type="pcap", source_path="filters.pcap", status="importing"
    )
    repository.store_packets(session_id, packets)

    expressions = [
        "tcp",
        "udp",
        "ip.src == 192.0.2.1",
        "ip.src >= 192.0.2.1",
        "ip.addr == 198.51.100.3",
        "ip.addr != 203.0.113.8",
        "tcp.port == 443",
        "tcp.port != 8000",
        "not tcp.port == 443",
        "udp.port == 5353",
        "frame.len > 0",
        "tcp.flags.syn == 1",
        "(tcp and tcp.port == 443) or udp",
        "not dns",
    ]
    for expression in expressions:
        expected = [
            record.record_id
            for record in packets
            if evaluate_filter(record, expression)
        ]
        actual = [
            row["id"]
            for row in repository.iter_packet_rows(
                session_id,
                expression=expression,
            )
        ]
        assert actual == expected, expression
        page_ids = [
            row["id"]
            for row in repository.get_packet_page(
                session_id,
                limit=2,
                expression=expression,
            )
        ]
        assert page_ids == expected[:2], expression
        assert repository.count_packets(session_id, expression) == len(expected)
    connection.close()


def test_repository_pagination_is_stable_and_count_does_not_load_all(tmp_path):
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    repository = PacketRepository(connection)
    session_id = repository.create_session(
        source_type="pcap", source_path="ordered.pcap", status="importing"
    )
    packets = [
        parse_packet(_packet(), number)
        for number in range(1, 8)
    ]
    for index, timestamp in enumerate(
        [
            "2024-01-01T00:00:03+00:00",
            "2024-01-01T00:00:01+00:00",
            "2024-01-01T00:00:02+00:00",
            "2024-01-01T00:00:01+00:00",
            "2024-01-01T00:00:04+00:00",
            "2024-01-01T00:00:00+00:00",
            "2024-01-01T00:00:02+00:00",
        ],
    ):
        packets[index].timestamp = timestamp
    repository.store_packets(session_id, packets)

    full_order = [
        row["id"] for row in repository.iter_packet_rows(session_id, batch_size=2)
    ]
    first_page = repository.get_packet_page(session_id, limit=3)
    second_page = repository.get_packet_page(session_id, limit=3, offset=3)
    assert [row["id"] for row in first_page + second_page] == full_order[:6]
    assert repository.count_packets(session_id) == 7
    assert "idx_packets_capture_timestamp" in {
        row["name"] for row in connection.execute("PRAGMA index_list(packets)")
    }
    connection.close()


def test_repository_pages_large_session_without_expanding_page_results(tmp_path):
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    repository = PacketRepository(connection)
    session_id = repository.create_session(
        source_type="pcap", source_path="many.pcap", status="importing"
    )
    packet_count = 1200
    for batch_start in range(1, packet_count + 1, 200):
        batch_end = min(batch_start + 200, packet_count + 1)
        batch = [
            parse_packet(_packet(), number)
            for number in range(batch_start, batch_end)
        ]
        repository.store_packets(session_id, batch)

    collected_numbers = []
    for offset in range(0, packet_count, 200):
        page = repository.get_packet_page(session_id, limit=200, offset=offset)
        assert len(page) == 200
        collected_numbers.extend(row["packet_number"] for row in page)
    assert collected_numbers == list(range(1, packet_count + 1))
    assert repository.count_packets(session_id) == packet_count
    connection.close()


def test_database_schema_migrates_existing_packet_rows(tmp_path):
    db_path = str(tmp_path / "legacy.db")
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """
        CREATE TABLE capture_sessions (
            id INTEGER PRIMARY KEY,
            source_type TEXT,
            source_path TEXT,
            start_timestamp TEXT,
            end_timestamp TEXT,
            status TEXT,
            packet_count INTEGER DEFAULT 0,
            byte_count INTEGER DEFAULT 0,
            capture_stats TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE packets (
            id INTEGER PRIMARY KEY,
            capture_session_id INTEGER,
            packet_number INTEGER,
            timestamp TEXT,
            source_address TEXT,
            destination_address TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            packet_length INTEGER,
            summary TEXT,
            metadata TEXT,
            details TEXT,
            original_reference TEXT
        );
        INSERT INTO capture_sessions(id, source_type, status)
        VALUES (1, 'pcap', 'completed');
        INSERT INTO packets(
            id, capture_session_id, packet_number, metadata, protocol
        ) VALUES (1, 1, 1, '{"tcp_flags_syn": 1}', 'TCP');
        """
    )
    connection.close()

    migrated = initialize_database(db_path)
    row = migrated.execute(
        "SELECT tcp_flags_syn FROM packets WHERE id = 1"
    ).fetchone()
    schema_version = migrated.execute("PRAGMA user_version").fetchone()[0]
    assert row["tcp_flags_syn"] == 1
    assert schema_version == 2
    migrated.close()


def test_filter_sql_rejects_unsupported_or_dangerous_expression(tmp_path):
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    repository = PacketRepository(connection)
    with pytest.raises(ValueError):
        repository.count_packets(1, "tcp; DROP TABLE packets")
    with pytest.raises(ValueError):
        repository.get_packet_page(1, expression="http")
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'packets'"
    ).fetchone() is not None
    connection.close()


def test_packet_rows_and_csv_export_stream_session_records(tmp_path):
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    repository = PacketRepository(connection)
    session_id = repository.create_session(
        source_type="pcap",
        source_path="sample.pcap",
        status="importing",
    )
    repository.store_packets(
        session_id,
        [parse_packet(_packet(), number) for number in range(1, 6)],
    )
    rows = repository.iter_packet_rows(session_id, batch_size=2)
    output = tmp_path / "packets.csv"
    CSVExporter.export_packets(str(output), rows)

    with output.open(newline="", encoding="utf-8-sig") as file_handle:
        exported = list(csv.DictReader(file_handle))
    assert [row["packet_number"] for row in exported] == ["1", "2", "3", "4", "5"]
    connection.close()


def test_repository_recovers_unfinished_sessions(tmp_path):
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    repository = PacketRepository(connection)
    importing_id = repository.create_session(
        source_type="pcap", source_path="one.pcap", status="importing"
    )
    capturing_id = repository.create_session(
        source_type="live", source_path="adapter", status="capturing"
    )
    complete_id = repository.create_session(
        source_type="pcap", source_path="two.pcap", status="completed"
    )

    assert repository.recover_interrupted_sessions() == 2
    assert repository.get_session(importing_id)["status"] == "interrupted"
    assert repository.get_session(capturing_id)["status"] == "interrupted"
    assert repository.get_session(complete_id)["status"] == "completed"
    connection.close()


def test_storage_worker_batches_and_drains_on_shutdown(tmp_path):
    db_path = str(tmp_path / "shaheen.db")
    connection = initialize_database(db_path)
    repository = PacketRepository(connection)
    session_id = repository.create_session(
        source_type="live", source_path="adapter", status="capturing"
    )
    worker = PacketStorageWorker(db_path, session_id, batch_size=2)
    records = [parse_packet(_packet(), number) for number in range(1, 4)]

    assert all(worker.submit(record) for record in records)
    worker.stop()
    assert len(repository.get_packet_page(session_id, limit=10)) == 3
    assert worker.packets_persisted == 3
    assert worker.dropped_packets == 0
    connection.close()


def test_storage_worker_does_not_queue_raw_packet_payloads(tmp_path, monkeypatch):
    db_path = str(tmp_path / "shaheen.db")
    connection = initialize_database(db_path)
    session_id = PacketRepository(connection).create_session(
        source_type="live", source_path="adapter", status="capturing"
    )
    store_entered = threading.Event()
    release_store = threading.Event()
    observed_raw_bytes = []
    original_store = PacketRepository.store_packets

    def blocked_store(self, session, packets, *, source_path=None):
        observed_raw_bytes.extend(packet.raw_bytes for packet in packets)
        store_entered.set()
        assert release_store.wait(timeout=2)
        return original_store(self, session, packets, source_path=source_path)

    monkeypatch.setattr(PacketRepository, "store_packets", blocked_store)
    worker = PacketStorageWorker(db_path, session_id, batch_size=1)
    original_packet = parse_packet(_packet(), 1)
    original_payload = original_packet.raw_bytes
    assert worker.submit(original_packet)
    assert store_entered.wait(timeout=2)
    assert observed_raw_bytes == [b""]
    assert original_packet.raw_bytes == original_payload
    release_store.set()
    worker.stop()
    connection.close()


def test_live_capture_sink_persists_normalized_packets(tmp_path):
    db_path = str(tmp_path / "shaheen.db")
    connection = initialize_database(db_path)
    repository = PacketRepository(connection)
    session_id = repository.create_session(
        source_type="live", source_path="adapter", status="capturing"
    )
    storage_worker = PacketStorageWorker(db_path, session_id)

    def fake_sniff(**kwargs):
        kwargs["prn"](_packet())
        raise RuntimeError("test capture complete")

    manager = CaptureManager(sniff_backend=fake_sniff)
    manager.capture_provider_status = lambda: (True, "mock provider")
    manager.session_id = session_id
    manager.packet_sink = storage_worker.submit
    manager.start_capture("explicit-interface")
    manager.capture_thread.join(timeout=2)
    manager.stop_capture()
    storage_worker.stop()

    packet_rows = repository.get_packet_page(session_id, limit=10)
    assert len(packet_rows) == 1
    assert packet_rows[0]["protocol"] == "TCP"
    assert packet_rows[0]["destination_port"] == 443
    assert manager.stats.packets_received == 1
    assert manager.stats.packets_dropped_from_storage_queue == 0
    connection.close()


def test_storage_worker_reports_queue_overflow_and_drains(tmp_path, monkeypatch):
    db_path = str(tmp_path / "shaheen.db")
    connection = initialize_database(db_path)
    session_id = PacketRepository(connection).create_session(
        source_type="live", source_path="adapter", status="capturing"
    )
    entered_store = threading.Event()
    release_store = threading.Event()
    original_store = PacketRepository.store_packets

    def blocked_store(self, session, packets, *, source_path=None):
        entered_store.set()
        assert release_store.wait(timeout=2)
        return original_store(self, session, packets, source_path=source_path)

    monkeypatch.setattr(PacketRepository, "store_packets", blocked_store)
    worker = PacketStorageWorker(db_path, session_id, queue_limit=1, batch_size=1)
    assert worker.submit(parse_packet(_packet(), 1))
    assert entered_store.wait(timeout=2)
    assert worker.submit(parse_packet(_packet(), 2))
    assert not worker.submit(parse_packet(_packet(), 3))
    release_store.set()
    worker.stop()

    session = PacketRepository(connection).get_session(session_id)
    assert session["packet_count"] == 2
    assert worker.packets_persisted == 2
    assert '"metadata_queue_dropped": 1' in session["capture_stats"]
    connection.close()


def test_offline_import_records_are_filtered_after_decode(tmp_path):
    capture_path = tmp_path / "packets.pcap"
    wrpcap(str(capture_path), [_packet(destination_port=443), _packet(destination_port=80)])
    records = read_pcap_file(str(capture_path))
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    repository = PacketRepository(connection)
    session_id = repository.create_session(
        source_type="pcap",
        source_path=str(capture_path),
        status="importing",
    )
    repository.store_packets(session_id, records, source_path=str(capture_path))

    stored_records = [
        packet_record_from_row(row)
        for row in repository.iter_packet_rows(session_id)
    ]
    matches = [
        record for record in stored_records
        if evaluate_filter(record, "tcp.port == 443")
    ]
    assert len(matches) == 1
    assert matches[0].destination_port == 443
    assert matches[0].raw_bytes == b""
    assert len(repository.get_packet_page(session_id, limit=10)) == 2
    connection.close()


def test_storage_worker_surfaces_write_failure(tmp_path, monkeypatch):
    db_path = str(tmp_path / "shaheen.db")
    connection = initialize_database(db_path)
    session_id = PacketRepository(connection).create_session(
        source_type="live", source_path="adapter", status="capturing"
    )

    def fail_store(*_args, **_kwargs):
        raise OSError("disk unavailable")

    monkeypatch.setattr(PacketRepository, "store_packets", fail_store)
    worker = PacketStorageWorker(db_path, session_id, batch_size=1)
    assert worker.submit(parse_packet(_packet(), 1))
    worker._thread.join(timeout=2)
    assert isinstance(worker.error, OSError)
    assert not worker.submit(parse_packet(_packet(), 2))
    with pytest.raises(RuntimeError, match="Packet metadata storage failed"):
        worker.stop()
    assert worker.dropped_packets == 2
    connection.close()
