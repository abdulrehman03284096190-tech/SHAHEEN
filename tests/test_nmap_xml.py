from __future__ import annotations

from types import SimpleNamespace

import pytest

from analyzer.nmap_xml import NmapHost, parse_nmap_xml
from database.connection import initialize_database
from gui.main_window import ShaheenMainWindow
from gui.theme import PALETTE


def test_parse_nmap_xml_reads_up_hosts_and_open_services(tmp_path):
    scan_file = tmp_path / "scan.xml"
    scan_file.write_text(
        """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.0.2.10" addrtype="ipv4"/>
            <hostnames><hostname name="web.example"/></hostnames>
            <ports>
              <port protocol="tcp" portid="22"><state state="closed"/></port>
              <port protocol="tcp" portid="443"><state state="open"/>
                <service name="https"/>
              </port>
            </ports>
          </host>
          <host>
            <status state="down"/>
            <address addr="192.0.2.11" addrtype="ipv4"/>
          </host>
        </nmaprun>""",
        encoding="utf-8",
    )

    assert parse_nmap_xml(scan_file) == [
        NmapHost("192.0.2.10", "web.example", ("443/tcp https",)),
    ]


def test_parse_nmap_xml_rejects_non_nmap_and_malformed_files(tmp_path):
    not_nmap = tmp_path / "other.xml"
    not_nmap.write_text("<root/>", encoding="utf-8")
    malformed = tmp_path / "broken.xml"
    malformed.write_text("<nmaprun>", encoding="utf-8")

    with pytest.raises(ValueError, match="not an Nmap scan result"):
        parse_nmap_xml(not_nmap)
    with pytest.raises(ValueError, match="Could not read Nmap XML"):
        parse_nmap_xml(malformed)


class FakeCanvas:
    def __init__(self) -> None:
        self.items: list[tuple[str, tuple, dict]] = []

    def delete(self, *_args) -> None:
        self.items.clear()

    def winfo_width(self) -> int:
        return 600

    def winfo_height(self) -> int:
        return 180

    def create_line(self, *args, **kwargs) -> None:
        self.items.append(("line", args, kwargs))

    def create_oval(self, *args, **kwargs) -> None:
        self.items.append(("oval", args, kwargs))

    def create_text(self, *args, **kwargs) -> None:
        self.items.append(("text", args, kwargs))


def test_dashboard_graph_draws_imported_hosts_and_observed_flow():
    canvas = FakeCanvas()
    window = SimpleNamespace(
        dashboard_network_canvas=canvas,
        _nmap_hosts={
            "192.0.2.10": NmapHost("192.0.2.10", "web", ("443/tcp https",)),
        },
        _dashboard_traffic_hosts=[
            ("192.0.2.10", 5),
            ("192.0.2.20", 5),
        ],
        _dashboard_network_edges=[("192.0.2.10", "192.0.2.20", 5)],
    )

    ShaheenMainWindow._render_dashboard_network_graph(window)

    assert any(item[0] == "line" for item in canvas.items)
    node_colors = [item[2]["fill"] for item in canvas.items if item[0] == "oval"]
    assert "#8B5CF6" in node_colors
    assert PALETTE["primary"] in node_colors
    assert any(
        item[0] == "text" and "443/tcp https" in item[2].get("text", "")
        for item in canvas.items
    )


def test_dashboard_network_data_uses_packet_records_for_graph_edges(tmp_path):
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    connection.execute(
        """
        INSERT INTO capture_sessions (source_type, source_path, status)
        VALUES ('pcap', 'sample.pcap', 'completed')
        """
    )
    connection.execute(
        """
        INSERT INTO packets (
            capture_session_id, packet_number, timestamp, source_address,
            destination_address, protocol, packet_length
        ) VALUES (1, 1, '2026-01-01T00:00:00Z', '192.0.2.10', '192.0.2.20', 'TCP', 128)
        """
    )
    canvas = FakeCanvas()
    window = SimpleNamespace(
        app=SimpleNamespace(db=connection),
        dashboard_network_canvas=canvas,
        _nmap_hosts={},
    )
    window._render_dashboard_network_graph = lambda: (
        ShaheenMainWindow._render_dashboard_network_graph(window)
    )

    ShaheenMainWindow._load_dashboard_network_data(window)

    assert window._dashboard_traffic_hosts == [
        ("192.0.2.10", 1),
        ("192.0.2.20", 1),
    ]
    assert window._dashboard_network_edges == [("192.0.2.10", "192.0.2.20", 1)]
    assert any(item[0] == "line" for item in canvas.items)
    connection.close()
