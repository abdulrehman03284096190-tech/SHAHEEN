from __future__ import annotations

import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

from scapy.all import IP, TCP, Ether

from analyzer.packet_parser import parse_packet
from config import settings as settings_module
from database.connection import initialize_database
from database.packet_repository import PacketRepository, packet_record_from_row
from gui import main_window as main_window_module
from gui.main_window import ShaheenMainWindow


def test_live_capture_metrics_show_capture_stats_and_elapsed_time():
    labels = {
        name: FakeLabel()
        for name in (
            "lkpi_recv",
            "lkpi_recv_s",
            "lkpi_acc",
            "lkpi_acc_s",
            "lkpi_pers",
            "lkpi_pers_s",
            "lkpi_pps",
            "lkpi_pps_s",
            "lkpi_data",
            "lkpi_data_s",
            "lkpi_lalerts",
            "lkpi_lalerts_s",
            "live_duration_label",
            "live_traffic_summary",
            "live_proto",
        )
    }
    window = SimpleNamespace(
        **labels,
        capture_manager=SimpleNamespace(
            stats=SimpleNamespace(
                packets_received=12,
                packets_accepted=10,
                packets_recorded=0,
                packets_delivered=10,
                packets_dropped_from_display_queue=2,
                packets_dropped_from_storage_queue=0,
                malformed_packets=2,
                recording=False,
            )
        ),
        _packet_storage_worker=None,
        _packets_persisted=9,
        _metadata_packets_dropped=0,
        _live_capture_started_at=100.0,
        _live_capture_stopped_at=105.0,
        _live_bytes_captured=2048,
        _live_protocol_counts=Counter({"TCP": 7, "DNS": 3}),
        live_traffic_graph=FakeGraphCanvas(),
        _live_traffic_samples=[],
        _live_traffic_last_sample_at=time.monotonic() - 1.1,
        _live_traffic_last_packets=0,
        _live_traffic_last_bytes=0,
        _live_traffic_final_sampled=False,
        _live_session_id=None,
        _last_live_capture_session_id=None,
        _last_live_alert_refresh=time.monotonic(),
    )
    window._render_live_traffic_graph = lambda: (
        ShaheenMainWindow._render_live_traffic_graph(window)
    )

    ShaheenMainWindow._refresh_live_capture_metrics(window)

    assert window.lkpi_recv.text == "12"
    assert window.lkpi_acc.text == "10"
    assert window.lkpi_pers.text == "9"
    assert window.lkpi_data.text == "2.0 KB"
    assert window.live_duration_label.text == "Duration: 00:00:05"
    assert "TCP: 7 packets" in window.live_proto.text
    assert "DNS: 3 packets" in window.live_proto.text
    assert "2 display drops" in window.live_traffic_summary.text
    assert len(window._live_traffic_samples) == 1
    assert len([item for item in window.live_traffic_graph.items if item[0] == "oval"]) == 2


def test_live_capture_metrics_refresh_before_next_graph_sample():
    labels = {
        name: FakeLabel()
        for name in (
            "lkpi_recv",
            "lkpi_recv_s",
            "lkpi_acc",
            "lkpi_acc_s",
            "lkpi_pers",
            "lkpi_pers_s",
            "lkpi_pps",
            "lkpi_pps_s",
            "lkpi_data",
            "lkpi_data_s",
            "lkpi_lalerts",
            "lkpi_lalerts_s",
            "live_duration_label",
            "live_traffic_summary",
            "live_proto",
        )
    }
    window = SimpleNamespace(
        **labels,
        capture_manager=SimpleNamespace(
            stats=SimpleNamespace(
                packets_received=1,
                packets_accepted=1,
                packets_recorded=0,
                packets_delivered=1,
                packets_dropped_from_display_queue=0,
                packets_dropped_from_storage_queue=0,
                malformed_packets=0,
                recording=False,
            )
        ),
        _packet_storage_worker=None,
        _packets_persisted=1,
        _metadata_packets_dropped=0,
        _live_capture_started_at=time.monotonic() - 0.1,
        _live_capture_stopped_at=None,
        _live_bytes_captured=64,
        _live_protocol_counts=Counter({"TCP": 1}),
        _live_traffic_samples=[],
        _live_traffic_last_sample_at=time.monotonic(),
        _live_traffic_last_packets=0,
        _live_traffic_last_bytes=0,
        _live_traffic_final_sampled=False,
        _live_session_id=None,
        _last_live_capture_session_id=None,
        _last_live_alert_refresh=time.monotonic(),
    )
    graph_refreshes = []
    window._render_live_traffic_graph = lambda: graph_refreshes.append(True)

    ShaheenMainWindow._refresh_live_capture_metrics(window)

    assert window._live_traffic_samples == []
    assert graph_refreshes == []
    assert window.lkpi_recv.text == "1"


def test_reports_refresh_uses_database_counts_and_history_files(tmp_path):
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    connection.execute(
        "INSERT INTO capture_sessions (source_type, source_path, status, packet_count, byte_count) VALUES (?, ?, ?, ?, ?)",
        ("live", "eth0", "completed", 150, 1024),
    )
    connection.execute(
        "INSERT INTO capture_sessions (source_type, source_path, status, packet_count, byte_count) VALUES (?, ?, ?, ?, ?)",
        ("pcap", "sample.pcap", "completed", 75, 512),
    )
    connection.execute(
        "INSERT INTO alerts (capture_session_id, rule_id, timestamp, severity, title, description, source_address, destination_address, status, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (1, "ALERT-1", "2024-01-01T00:00:00Z", "critical", "Critical alert", "desc", "1.1.1.1", "2.2.2.2", "new", 0.98),
    )
    connection.execute(
        "INSERT INTO alerts (capture_session_id, rule_id, timestamp, severity, title, description, source_address, destination_address, status, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (2, "ALERT-2", "2024-01-01T01:00:00Z", "medium", "Medium alert", "desc", "3.3.3.3", "4.4.4.4", "new", 0.6),
    )
    connection.execute(
        "INSERT INTO investigations (title, description, status) VALUES (?, ?, ?)",
        ("Case A", "Example", "open"),
    )
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    (report_dir / "sample.csv").write_text("id,name\n1,ok\n", encoding="utf-8")

    window = ShaheenMainWindow.__new__(ShaheenMainWindow)
    window.app = SimpleNamespace(
        db=connection,
        settings=SimpleNamespace(report_path=str(report_dir)),
        logger=SimpleNamespace(exception=lambda *args, **kwargs: None),
    )
    window.rkpi_sess = FakeLabel()
    window.rkpi_sess_s = FakeLabel()
    window.rkpi_pkt = FakeLabel()
    window.rkpi_pkt_s = FakeLabel()
    window.rkpi_alt = FakeLabel()
    window.rkpi_alt_s = FakeLabel()
    window.rkpi_crit = FakeLabel()
    window.rkpi_crit_s = FakeLabel()
    window.rkpi_inv = FakeLabel()
    window.rkpi_inv_s = FakeLabel()
    window.rkpi_rep = FakeLabel()
    window.rkpi_rep_s = FakeLabel()
    window.report_history_table = FakeTree()

    ShaheenMainWindow._refresh_reports(window)

    assert window.rkpi_sess.text == "2"
    assert window.rkpi_pkt.text == "225"
    assert window.rkpi_alt.text == "2"
    assert window.rkpi_crit.text == "1"
    assert window.rkpi_inv.text == "1"
    assert window.rkpi_rep.text == "1"
    assert len(window.report_history_table.rows) == 1
    connection.close()


def test_selected_report_can_be_downloaded(tmp_path, monkeypatch):
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    report = report_dir / "security-report.json"
    report.write_text('{"status": "ready"}', encoding="utf-8")
    download_dir = tmp_path / "downloads"
    download_dir.mkdir()
    destination = download_dir / report.name

    window = ShaheenMainWindow.__new__(ShaheenMainWindow)
    window.app = SimpleNamespace(
        settings=SimpleNamespace(report_path=str(report_dir)),
        logger=SimpleNamespace(exception=lambda *args, **kwargs: None),
    )
    window.report_history_table = FakeTree()
    window.packet_label = FakeLabel()
    window.report_empty_label = FakeLabel()
    window._update_report_selection_ui = lambda *_args: None
    window._style_report_history_table = lambda: None
    ShaheenMainWindow._load_report_history(window)
    window.report_history_table.selection_set("report-0")
    monkeypatch.setattr(
        main_window_module.filedialog,
        "asksaveasfilename",
        lambda **_kwargs: str(destination),
    )

    ShaheenMainWindow._download_selected_report(window)

    assert destination.read_text(encoding="utf-8") == '{"status": "ready"}'
    assert window.packet_label.text == f"Report downloaded to {destination}"


def test_frozen_settings_use_writable_per_user_application_data(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_module, "load_dotenv", lambda *_args: None)
    monkeypatch.setattr(settings_module.sys, "frozen", True, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    for variable in ("DATABASE_PATH", "CAPTURE_PATH", "REPORT_PATH", "LOG_PATH"):
        monkeypatch.delenv(variable, raising=False)

    settings = settings_module.load_settings()
    app_data = tmp_path / "Shaheen"
    assert settings.database_path == str(app_data / "data" / "shaheen.db")
    assert Path(settings.capture_path) == app_data / "captures"
    assert Path(settings.report_path) == app_data / "reports_output"
    assert Path(settings.log_path) == app_data / "logs" / "shaheen.log"
    assert all(
        path.is_dir()
        for path in (
            app_data / "data",
            app_data / "captures",
            app_data / "reports_output",
            app_data / "logs",
        )
    )
    connection = initialize_database(settings.database_path)
    connection.close()


class FakeTree:
    def __init__(self) -> None:
        self.rows: dict[str, tuple[str, ...]] = {}
        self.selected: tuple[str, ...] = ()

    def get_children(self, _item: str = "") -> tuple[str, ...]:
        return tuple(self.rows)

    def delete(self, *items: str) -> None:
        for item in items:
            self.rows.pop(item, None)

    def insert(self, _parent: str, _index: str, *, iid: str, values, **_kwargs) -> None:
        self.rows[iid] = tuple(values)

    def tag_configure(self, *_args, **_kwargs) -> None:
        return

    def selection_set(self, iid: str) -> None:
        self.selected = (iid,)

    def selection(self) -> tuple[str, ...]:
        return self.selected

    def focus(self, _iid: str) -> None:
        return

    def see(self, _iid: str) -> None:
        return


class FakeText:
    def __init__(self) -> None:
        self.content = ""

    def delete(self, *_args) -> None:
        self.content = ""

    def insert(self, _index: str, text: str) -> None:
        self.content += text


class FakeLabel:
    def __init__(self) -> None:
        self.text = ""
        self.visible = False

    def configure(self, *, text: str) -> None:
        self.text = text

    def place(self, **_kwargs) -> None:
        self.visible = True

    def place_forget(self) -> None:
        self.visible = False


class FakeGraphCanvas:
    def __init__(self) -> None:
        self.items: list[tuple[str, tuple, dict]] = []

    def delete(self, *_args) -> None:
        self.items.clear()

    def winfo_width(self) -> int:
        return 420

    def winfo_height(self) -> int:
        return 94

    def create_text(self, *args, **kwargs) -> None:
        self.items.append(("text", args, kwargs))

    def create_line(self, *args, **kwargs) -> None:
        self.items.append(("line", args, kwargs))

    def create_oval(self, *args, **kwargs) -> None:
        self.items.append(("oval", args, kwargs))


def test_live_traffic_graph_draws_packet_and_bandwidth_series():
    canvas = FakeGraphCanvas()
    window = SimpleNamespace(
        live_traffic_graph=canvas,
        _live_traffic_samples=[
            ("12:00:01", 10.0, 2048.0),
            ("12:00:02", 30.0, 4096.0),
            ("12:00:03", 15.0, 1024.0),
        ],
    )

    ShaheenMainWindow._render_live_traffic_graph(window)

    series = [
        item for item in canvas.items
        if item[0] == "line" and item[2].get("smooth")
    ]
    assert len(series) == 2
    assert series[0][2]["fill"] != series[1][2]["fill"]
    assert any(item[2].get("text") == "30 pkt/s" for item in canvas.items)
    assert any(item[2].get("text") == "4.0 KB/s" for item in canvas.items)


def _record(number: int = 1):
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=12345, dport=443, flags="S")
    )
    return parse_packet(packet, number)


def test_packet_table_renders_persisted_packet_fields_and_selection(tmp_path):
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    repository = PacketRepository(connection)
    session_id = repository.create_session(
        source_type="pcap",
        source_path="sample.pcap",
        status="completed",
    )
    repository.store_packets(session_id, [_record()])
    packet = packet_record_from_row(repository.get_packet_page(session_id, limit=1)[0])

    selected = []
    window = SimpleNamespace(
        selected_packet=None,
        _current_session_id=session_id,
        _live_capture_active=False,
        _page_size=200,
        MAX_PACKET_ROWS=2000,
        packet_records=[packet],
        displayed_packets=[],
        packet_table=FakeTree(),
        _packet_by_iid={},
        packet_empty_label=FakeLabel(),
        packet_details=FakeText(),
        packet_hex=FakeText(),
        _selection_cancel_event=None,
        _details_packet=None,
        _packet_identity=ShaheenMainWindow._packet_identity,
        _packet_table_iid=ShaheenMainWindow._packet_table_iid,
        _packet_table_values=ShaheenMainWindow._packet_table_values,
        _update_table_empty_state=lambda: ShaheenMainWindow._update_table_empty_state(window),
    )
    window._select_packet_record = lambda selected_packet: (
        selected.append(selected_packet),
        window.packet_table.selection_set(f"record-{selected_packet.record_id}"),
    )
    ShaheenMainWindow._render_packet_table(window, [packet])

    iid = f"record-{packet.record_id}"
    assert window.packet_table.rows[iid] == (
        "1",
        packet.timestamp.replace("T", " "),
        "192.0.2.10:12345",
        "198.51.100.20:443",
        "TCP",
        f"{packet.packet_length:,}",
        packet.summary,
    )
    assert window.packet_table.selected == (iid,)
    assert selected == [packet]
    assert not window.packet_empty_label.visible
    connection.close()


def test_packet_table_empty_states_explain_session_and_filter_results():
    empty_label = FakeLabel()
    window = SimpleNamespace(
        displayed_packets=[],
        _live_capture_active=False,
        _import_cancel_event=None,
        _current_session_id=None,
        _current_filter="",
        _matching_packet_count=0,
        packet_empty_label=empty_label,
    )
    ShaheenMainWindow._update_table_empty_state(window)
    assert empty_label.visible
    assert "No capture loaded" in empty_label.text

    window._import_cancel_event = object()
    ShaheenMainWindow._update_table_empty_state(window)
    assert "Import in progress" in empty_label.text

    window._import_cancel_event = None
    window._current_session_id = 7
    window._current_filter = "tcp"
    ShaheenMainWindow._update_table_empty_state(window)
    assert "No packets match" in empty_label.text

    window._current_filter = ""
    ShaheenMainWindow._update_table_empty_state(window)
    assert "session contains no packets" in empty_label.text


def test_selected_packet_details_and_hex_view_use_same_packet():
    packet = _record()
    details = FakeText()
    hex_view = FakeText()
    window = SimpleNamespace(
        _details_packet=None,
        selected_packet=None,
        packet_details=details,
        packet_hex=hex_view,
    )

    ShaheenMainWindow._show_packet_details(window, packet)

    assert "TCP" in details.content
    assert str(packet.packet_number) in details.content
    assert hex_view.content == packet.hex_dump
    assert packet.raw_bytes.hex(" ")[:16] in hex_view.content
