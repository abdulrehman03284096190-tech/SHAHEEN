import time
import threading

import pytest
from scapy.all import Ether, IP, TCP, wrpcap
from scapy.utils import PcapNgWriter

from analyzer.filter_engine import evaluate_filter
from analyzer.packet_parser import PacketRecord, parse_packet
from capture.capture_manager import CaptureManager
from capture.interface_manager import InterfaceDiscoveryError, InterfaceManager
from capture.pcap_reader import (
    CaptureReadError,
    import_capture,
    read_packet_at,
    read_pcap_file,
    read_pcap_stream,
)


def _make_packet() -> Ether:
    return Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=12345, dport=443, flags="S")


def test_pcapng_import_and_timestamp_preservation(tmp_path) -> None:
    path = tmp_path / "sample.pcapng"
    packet = _make_packet()
    writer = PcapNgWriter(str(path))
    writer.write(packet)
    writer.write(packet)
    writer.close()

    records = read_pcap_file(str(path))
    assert len(records) == 2
    assert all(record.timestamp for record in records)
    assert records[0].protocol == "TCP"
    assert len(list(read_pcap_stream(str(path)))) == 2


def test_streaming_import_reports_progress_and_supports_cancellation(tmp_path) -> None:
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), [_make_packet() for _ in range(5)])
    received = []
    progress = []
    cancel_event = threading.Event()

    def on_packet(record):
        received.append(record)
        if len(received) == 2:
            cancel_event.set()

    result = import_capture(
        str(path),
        on_packet,
        cancel_event=cancel_event,
        on_progress=progress.append,
        progress_interval=1,
    )
    assert result.cancelled is True
    assert result.packets_read == 2
    assert [record.packet_number for record in received] == [1, 2]
    assert progress
    assert progress[-1].total_bytes == path.stat().st_size
    assert progress[-1].bytes_read > 0


def test_invalid_capture_header_is_reported(tmp_path) -> None:
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"not a capture")
    try:
        import_capture(path, lambda _packet: None)
        raise AssertionError("Expected malformed capture error")
    except CaptureReadError:
        pass


def test_filter_integration_with_parsed_packet() -> None:
    packet = parse_packet(_make_packet(), 1)
    assert packet.protocol == "TCP"
    assert evaluate_filter(packet, "tcp")
    assert evaluate_filter(packet, "ip.src == 192.168.1.10")
    assert evaluate_filter(packet, "tcp.flags.syn == 1")


def test_offline_import_can_omit_payload_bytes_and_load_one_packet_lazily(tmp_path) -> None:
    path = tmp_path / "lazy.pcap"
    first = _make_packet()
    second = Ether() / IP(src="192.0.2.5", dst="198.51.100.8") / TCP(sport=4321, dport=80)
    wrpcap(str(path), [first, second])
    lightweight_records = []

    import_capture(
        path,
        lightweight_records.append,
        include_raw_bytes=False,
    )

    assert len(lightweight_records) == 2
    assert all(record.raw_bytes == b"" for record in lightweight_records)
    selected = read_packet_at(path, 2)
    assert selected.packet_number == 2
    assert selected.raw_bytes == bytes(second)
    assert selected.source_address == "192.0.2.5"


def test_read_packet_at_rejects_out_of_range_number(tmp_path) -> None:
    path = tmp_path / "one.pcap"
    wrpcap(str(path), [_make_packet()])
    with pytest.raises(CaptureReadError, match="beyond the end"):
        read_packet_at(path, 2)


def test_capture_manager_start_stop() -> None:
    manager = CaptureManager(sniff_backend=lambda **_kwargs: manager.stop_event.wait(0.01))
    manager.capture_provider_status = lambda: (True, "mock provider")
    manager.start_capture("loopback")
    time.sleep(0.1)
    manager.stop_capture()
    assert manager.capture_thread is None


def test_capture_manager_handles_backend_error(monkeypatch) -> None:
    def _fail(**_kwargs):
        raise RuntimeError("Npcap unavailable")

    manager = CaptureManager(sniff_backend=_fail)
    manager.capture_provider_status = lambda: (True, "mock provider")
    manager.start_capture("loopback")
    time.sleep(0.2)
    assert manager.consumer() == (
        "error",
        "Capture backend unavailable. Install Npcap with WinPcap API-compatible mode and restart Shaheen. Details: Npcap unavailable",
    )
    manager.stop_capture()


def test_capture_manager_bounds_display_queue_and_counts_drops() -> None:
    packet = _make_packet()

    def fake_sniff(**kwargs):
        kwargs["prn"](packet)
        kwargs["prn"](packet)
        raise RuntimeError("capture test complete")

    manager = CaptureManager(queue_limit=1, sniff_backend=fake_sniff)
    manager.capture_provider_status = lambda: (True, "mock provider")
    manager.start_capture("explicit-interface")
    manager.capture_thread.join(timeout=2)

    stats = manager.stats
    assert stats.packets_received == 2
    assert stats.packets_accepted == 2
    assert stats.packets_dropped_from_display_queue == 1
    assert manager.packet_queue.qsize() == 1
    manager.stop_capture()


@pytest.mark.parametrize("suffix", [".pcap", ".pcapng"])
def test_recording_is_finalized_and_can_be_reopened(tmp_path, suffix) -> None:
    packet = _make_packet()
    packet.time = 1_700_000_000.25
    release_packet = threading.Event()

    def fake_sniff(**kwargs):
        release_packet.wait(timeout=2)
        kwargs["prn"](packet)
        raise RuntimeError("test capture finished")

    manager = CaptureManager(sniff_backend=fake_sniff)
    manager.capture_provider_status = lambda: (True, "mock provider")
    recording_path = tmp_path / f"captured{suffix}"
    manager.start_capture("explicit-interface", record_path=str(recording_path))
    release_packet.set()
    manager.capture_thread.join(timeout=2)

    assert not manager.capture_thread.is_alive()
    assert manager.stats.packets_received == 1
    assert manager.stats.packets_recorded == 1
    records = read_pcap_file(str(recording_path))
    assert len(records) == 1
    assert records[0].packet_number == 1
    assert records[0].timestamp == "2023-11-14T22:13:20.250000+00:00"
    manager.stop_capture()


def test_recording_refuses_overwrite_without_explicit_approval(tmp_path) -> None:
    recording_path = tmp_path / "existing.pcap"
    recording_path.write_bytes(b"keep")
    manager = CaptureManager(sniff_backend=lambda **_kwargs: manager.stop_event.wait(0.01))
    manager.capture_provider_status = lambda: (True, "mock provider")
    manager.start_capture("explicit-interface")
    try:
        manager.start_recording(str(recording_path))
        raise AssertionError("Expected overwrite protection")
    except Exception as exc:
        assert "Refusing to overwrite" in str(exc)
    manager.stop_capture()
    assert recording_path.read_bytes() == b"keep"


def test_capture_provider_unavailable_has_actionable_error(monkeypatch) -> None:
    manager = CaptureManager()
    monkeypatch.setattr(manager, "capture_provider_status", lambda: (False, "Npcap unavailable"))
    try:
        manager.start_capture("explicit-interface")
        raise AssertionError("Expected missing provider error")
    except Exception as exc:
        assert "Npcap unavailable" in str(exc)


def test_interface_discovery_returns_real_metadata(monkeypatch) -> None:
    monkeypatch.setattr(
        "capture.interface_manager.get_windows_if_list",
        lambda: [
            {
                "name": "Test adapter",
                "description": "VirtualBox host network",
                "mac": "02:00:00:00:00:01",
                "ips": ["192.0.2.10", "2001:db8::10"],
                "index": 7,
            }
        ],
    )
    interfaces = InterfaceManager.list_interfaces()
    assert len(interfaces) == 1
    assert interfaces[0].name == "Test adapter"
    assert interfaces[0].mac_address == "02:00:00:00:00:01"
    assert interfaces[0].addresses == ("192.0.2.10", "2001:db8::10")
    assert interfaces[0].is_virtual is True


def test_interface_discovery_failure_is_not_replaced_with_fake_interface(monkeypatch) -> None:
    def fail():
        raise OSError("adapter query failed")

    monkeypatch.setattr("capture.interface_manager.get_windows_if_list", fail)
    try:
        InterfaceManager.list_interfaces()
        raise AssertionError("Expected interface discovery failure")
    except InterfaceDiscoveryError as exc:
        assert "adapter query failed" in str(exc)


def test_read_pcap_file_rejects_unsupported_format(tmp_path) -> None:
    bad = tmp_path / "bad.txt"
    bad.write_text("not a capture", encoding="utf-8")
    try:
        read_pcap_file(str(bad))
        raise AssertionError("Expected ValueError for unsupported capture format")
    except ValueError:
        pass
