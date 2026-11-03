from __future__ import annotations

from types import SimpleNamespace

from gui.main_window import ShaheenMainWindow
from gui.theme import PALETTE


class FakeCanvas:
    def __init__(self) -> None:
        self.items: list[tuple[str, tuple, dict]] = []

    def delete(self, *_args) -> None:
        self.items.clear()

    def winfo_width(self) -> int:
        return 420

    def winfo_height(self) -> int:
        return 140

    def create_text(self, *args, **kwargs) -> None:
        self.items.append(("text", args, kwargs))

    def create_rectangle(self, *args, **kwargs) -> None:
        self.items.append(("rectangle", args, kwargs))

    def create_line(self, *args, **kwargs) -> None:
        self.items.append(("line", args, kwargs))

    def create_oval(self, *args, **kwargs) -> None:
        self.items.append(("oval", args, kwargs))


def test_dashboard_protocol_chart_draws_bars_and_values():
    canvas = FakeCanvas()
    window = SimpleNamespace(
        dashboard_protocol_canvas=canvas,
        _dashboard_protocol_data=[("TCP", 80), ("UDP", 20)],
    )
    window._render_dashboard_bar_chart = lambda *args: (
        ShaheenMainWindow._render_dashboard_bar_chart(window, *args)
    )

    ShaheenMainWindow._render_dashboard_protocol_chart(window)

    assert len([item for item in canvas.items if item[0] == "rectangle"]) == 4
    assert any(item[2].get("text") == "80" for item in canvas.items)
    assert any(item[2].get("text") == "20" for item in canvas.items)
    assert any(item[2].get("fill") == PALETTE["primary"] for item in canvas.items)


def test_dashboard_alert_chart_uses_severity_colors():
    canvas = FakeCanvas()
    window = SimpleNamespace(
        dashboard_alerts_canvas=canvas,
        _dashboard_alert_data=[("critical", 3), ("medium", 5)],
    )
    window._render_dashboard_bar_chart = lambda *args: (
        ShaheenMainWindow._render_dashboard_bar_chart(window, *args)
    )

    ShaheenMainWindow._render_dashboard_alert_chart(window)

    bar_colors = [
        item[2]["fill"]
        for item in canvas.items
        if item[0] == "rectangle" and item[2].get("fill") != PALETTE["bg_card_alt"]
    ]
    assert PALETTE["danger"] in bar_colors
    assert PALETTE["warning"] in bar_colors


def test_dashboard_timeline_draws_packet_count_series_and_empty_state():
    canvas = FakeCanvas()
    window = SimpleNamespace(
        dashboard_timeline_canvas=canvas,
        _dashboard_timeline_data=[
            ("2026-11-03T09", 4),
            ("2026-11-03T10", 12),
            ("2026-11-03T11", 7),
        ],
    )

    ShaheenMainWindow._render_dashboard_timeline(window)

    assert any(item[0] == "line" and item[2].get("smooth") for item in canvas.items)
    assert len([item for item in canvas.items if item[0] == "oval"]) == 3
    assert any(item[2].get("text") == "11-03 09" for item in canvas.items)

    window._dashboard_timeline_data = []
    ShaheenMainWindow._render_dashboard_timeline(window)
    assert any(
        item[0] == "text" and "No timestamped packet data" in item[2].get("text", "")
        for item in canvas.items
    )
