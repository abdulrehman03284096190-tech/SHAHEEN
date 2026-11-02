from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scapy.all import Ether, IP, TCP

from analyzer.packet_parser import parse_packet
from config import settings as settings_module
from database.connection import initialize_database
from database.packet_repository import PacketRepository, packet_record_from_row
from gui.main_window import ShaheenMainWindow


def test_frozen_settings_use_writable_per_user_application_data(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_module, "load_dotenv", lambda: None)
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
