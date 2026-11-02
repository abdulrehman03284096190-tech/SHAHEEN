from __future__ import annotations

import json
import queue
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import customtkinter as ctk
except Exception:  # pragma: no cover
    class _DummyCTk:  # type: ignore[no-redef]
        def __getattr__(self, _item):
            raise RuntimeError("customtkinter is required to run the GUI")
    ctk = _DummyCTk()

from analyzer.filter_engine import FilterError, compile_filter_sql, evaluate_filter
from analyzer.packet_parser import PacketRecord
from capture.capture_manager import CaptureManager
from capture.interface_manager import CaptureInterface, InterfaceDiscoveryError
from capture.pcap_reader import ImportProgress, import_capture, read_packet_at
from config.settings import (
    load_settings,
    save_persisted_settings,
    validate_editable_settings,
)
from core.application import ShaheenApplication
from database.alert_repository import AlertRepository
from database.connection import initialize_database
from database.packet_repository import (
    PacketRepository,
    PacketStorageWorker,
    packet_record_from_row,
)
from detection.detection_engine import DetectionEngine
from investigations.case_manager import InvestigationManager
from reports.csv_export import CSVExporter
from reports.pdf_report import PDFReport
from gui.theme import PALETTE
from gui.icons import svg_data


class _AutoScrollbar(ttk.Scrollbar):
    def set(self, first: str, last: str) -> None:
        if float(first) <= 0.0 and float(last) >= 1.0:
            self.grid_remove()
        else:
            self.grid()
        super().set(first, last)


class ShaheenMainWindow(ctk.CTk):
    MAX_PACKET_ROWS = 2000

    def __init__(self, app: ShaheenApplication | None = None) -> None:
        super().__init__()
        self.app = app or ShaheenApplication(load_settings())
        ctk.set_appearance_mode(self.app.settings.theme)
        self.capture_manager = CaptureManager()
        self.investigations = InvestigationManager(self.app.db)
        self.packet_records: list = []
        self.displayed_packets: list = []
        self.selected_packet = None
        self._details_packet = None
        self._current_session_id: int | None = None
        self._offline_source_path: str | None = None
        self._current_filter = ""
        self._page_size = 200
        self._current_page = 0
        self._matching_packet_count = 0
        self._page_load_active = False
        self._selection_request_id = 0
        self._selection_cancel_event: threading.Event | None = None
        self.active_investigation_id: int | None = None
        self._import_cancel_event: threading.Event | None = None
        self._import_thread: threading.Thread | None = None
        self._closing = False
        self._background_workers: set[threading.Thread] = set()
        self._workers_lock = threading.Lock()
        self._import_events: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=256)
        self._interface_by_label: dict[str, CaptureInterface] = {}
        self._display_paused = False
        self._display_paused_packets = 0
        self._live_capture_active = False
        self._live_session_id: int | None = None
        self._packet_storage_worker: PacketStorageWorker | None = None
        self._packets_persisted = 0
        self._metadata_packets_dropped = 0

        self.title(f"{self.app.settings.app_name} — Network Traffic Analysis")
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        initial_width = min(1280, max(860, int(screen_width * 0.92)))
        initial_height = min(780, max(560, int(screen_height * 0.88)))
        self.geometry(f"{initial_width}x{initial_height}")
        self.minsize(min(980, initial_width), min(580, initial_height))
        self.configure(fg_color=PALETTE["bg_app"])
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=260, corner_radius=0, fg_color=PALETTE["bg_sidebar"])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_columnconfigure(0, weight=1)
        self.sidebar.grid_rowconfigure(10, weight=1)

        title_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        title_frame.grid(row=0, column=0, sticky="ew", padx=18, pady=(24, 16))
        ctk.CTkLabel(
            title_frame,
            text="SHAHEEN",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=PALETTE["text_primary"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_frame,
            text="NETWORK TRAFFIC ANALYSIS",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=PALETTE["text_label"],
        ).pack(anchor="w", pady=(4, 0))
        divider = ctk.CTkFrame(self.sidebar, height=1, fg_color=PALETTE["border"])
        divider.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 16))

        self._nav_buttons = {}
        self._current_nav = "Packet Analyzer"
        nav_items = (
            ("Dashboard", "dashboard"),
            ("Live Capture", "live"),
            ("Packet Analyzer", "analyzer"),
            ("Alerts", "alerts"),
            ("Reports", "reports"),
            ("Settings", "settings"),
        )
        for row, (label, icon_name) in enumerate(nav_items, start=2):
            btn = ctk.CTkButton(
                self.sidebar,
                text="   " + label,
                anchor="w",
                height=42,
                corner_radius=8,
                fg_color="transparent",
                hover_color=PALETTE["nav_hover"],
                text_color=PALETTE["text_label"],
                font=ctk.CTkFont(size=12),
                command=lambda name=label: self._select_navigation(name),
                compound="left",
            )
            try:
                from PIL import Image
                import io, base64
                data = svg_data(icon_name)
                if data:
                    img_data = base64.b64decode(data.split(",", 1)[1]) if "," in data else None
                    if img_data:
                        img = Image.open(io.BytesIO(img_data))
                        ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(18, 18))
                        btn.configure(image=ctk_img)
            except Exception:
                pass
            btn.grid(row=row, column=0, padx=12, pady=3, sticky="ew")
            self._nav_buttons[label] = btn
        self._current_nav = "Packet Analyzer"
        try:
            self._update_nav_active_state(self._current_nav)
        except Exception:
            pass
        sidebar_footer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        sidebar_footer.grid(row=10, column=0, sticky="ew", padx=18, pady=(16, 20))
        ctk.CTkLabel(
            sidebar_footer,
            text="v1.0.0",
            justify="left",
            text_color=PALETTE["text_label"],
            font=ctk.CTkFont(size=10),
        ).pack(anchor="w")
        ctk.CTkLabel(
            sidebar_footer,
            text="Network Analysis System",
            justify="left",
            text_color=PALETTE["text_label"],
            font=ctk.CTkFont(size=10),
        ).pack(anchor="w", pady=(2, 0))

        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color=PALETTE["bg_content"])
        self.content.grid(row=0, column=1, sticky="nsew", padx=(8, 12), pady=(10, 4))
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(3, weight=1)

        header_frame = ctk.CTkFrame(self.content, fg_color=PALETTE["bg_header"] if "bg_header" in PALETTE else "#111827")
        header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 8))
        header_frame.grid_columnconfigure(0, weight=1)
        self.header = ctk.CTkLabel(
            header_frame,
            text="Packet Analyzer",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=PALETTE["text_primary"],
            anchor="w",
        )
        self.header.grid(row=0, column=0, sticky="w", padx=24, pady=(18, 18))
        self.header_state = ctk.CTkLabel(
            header_frame,
            text="Capture idle",
            text_color=PALETTE["text_label"],
            font=ctk.CTkFont(size=12),
        )
        self.header_state.grid(row=0, column=1, padx=(12, 24), pady=(18, 18), sticky="e")

        self.toolbar = ctk.CTkFrame(
            self.content,
            fg_color=PALETTE["bg_panel"],
            border_width=1,
            border_color=PALETTE["border"],
        )
        self.toolbar.grid(row=1, column=0, sticky="ew", padx=8, pady=(2, 8))
        self.toolbar.grid_columnconfigure(0, weight=1)

        capture_group = ctk.CTkFrame(self.toolbar, fg_color="transparent")
        capture_group.grid(row=0, column=0, sticky="ew", padx=10, pady=(5, 1))
        capture_group.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            capture_group,
            text="CAPTURE",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=PALETTE["text_label"],
            width=92,
            anchor="w",
        ).grid(row=0, column=0, padx=4, pady=4, sticky="w")
        self.interface_menu = ctk.CTkOptionMenu(
            capture_group,
            values=["Select interface"],
            command=self._select_interface,
            width=180,
            fg_color="#25354A",
            button_color="#334B67",
        )
        self.interface_menu.grid(row=0, column=1, padx=4, pady=4, sticky="ew")
        self.interface_menu.set("Select interface")
        self.refresh_interfaces_button = ctk.CTkButton(
            capture_group,
            text="Refresh",
            width=78,
            command=self._refresh_interfaces,
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["nav_hover"],
        )
        self.refresh_interfaces_button.grid(row=0, column=2, padx=4, pady=4)
        self.start_capture_button = ctk.CTkButton(
            capture_group,
            text="Start capture",
            width=100,
            command=self._start_live_capture,
            fg_color=PALETTE["success"],
            hover_color=PALETTE["success_hover"],
        )
        self.start_capture_button.grid(row=0, column=3, padx=4, pady=4)
        self.stop_capture_button = ctk.CTkButton(
            capture_group,
            text="Stop capture",
            width=100,
            command=self._stop_live_capture,
            fg_color=PALETTE["danger"],
            hover_color=PALETTE["danger_hover"],
        )
        self.stop_capture_button.grid(row=0, column=4, padx=4, pady=4)
        self.pause_display_button = ctk.CTkButton(
            capture_group,
            text="Pause display",
            width=104,
            command=self._toggle_display_pause,
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["nav_hover"],
        )
        self.pause_display_button.grid(row=0, column=5, padx=4, pady=4)

        file_group = ctk.CTkFrame(self.toolbar, fg_color="transparent")
        file_group.grid(row=1, column=0, sticky="ew", padx=10, pady=1)
        ctk.CTkLabel(
            file_group,
            text="FILE & RECORDING",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=PALETTE["text_label"],
            width=92,
            anchor="w",
        ).grid(row=0, column=0, padx=4, pady=4, sticky="w")
        self.import_button = ctk.CTkButton(
            file_group,
            text="Import capture",
            width=112,
            command=self._import_file,
            fg_color=PALETTE["primary"],
            hover_color=PALETTE["primary_hover"],
        )
        self.import_button.grid(row=0, column=1, padx=4, pady=4)
        self.cancel_import_button = ctk.CTkButton(
            file_group,
            text="Cancel import",
            width=100,
            command=self._cancel_import,
            state="disabled",
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["nav_hover"],
        )
        self.cancel_import_button.grid(row=0, column=2, padx=4, pady=4)
        self.start_recording_button = ctk.CTkButton(
            file_group,
            text="Start recording",
            width=116,
            command=self._start_recording,
            fg_color=PALETTE["primary"],
            hover_color=PALETTE["primary_hover"],
        )
        self.start_recording_button.grid(row=0, column=3, padx=4, pady=4)
        self.stop_recording_button = ctk.CTkButton(
            file_group,
            text="Stop recording",
            width=116,
            command=self._stop_recording,
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["nav_hover"],
        )
        self.stop_recording_button.grid(row=0, column=4, padx=4, pady=4)

        display_group = ctk.CTkFrame(self.toolbar, fg_color="transparent")
        display_group.grid(row=2, column=0, sticky="ew", padx=10, pady=1)
        display_group.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            display_group,
            text="DISPLAY FILTER",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=PALETTE["text_label"],
            width=92,
            anchor="w",
        ).grid(row=0, column=0, padx=4, pady=4, sticky="w")
        self.filter_entry = ctk.CTkEntry(
            display_group,
            placeholder_text="e.g. tcp.port == 443 or dns",
            height=34,
        )
        self.filter_entry.grid(row=0, column=1, padx=4, pady=4, sticky="ew")
        self.apply_filter_button = ctk.CTkButton(
            display_group,
            text="Apply filter",
            width=98,
            command=self._apply_filter,
            fg_color=PALETTE["primary"],
            hover_color=PALETTE["primary_hover"],
        )
        self.apply_filter_button.grid(row=0, column=2, padx=4, pady=4)
        self.clear_filter_button = ctk.CTkButton(
            display_group,
            text="Clear",
            width=72,
            command=self._clear_filter,
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["nav_hover"],
        )
        self.clear_filter_button.grid(row=0, column=3, padx=4, pady=4)

        navigation_group = ctk.CTkFrame(self.toolbar, fg_color="transparent")
        navigation_group.grid(row=3, column=0, sticky="ew", padx=10, pady=(1, 4))
        navigation_group.grid_columnconfigure(2, weight=1)
        ctk.CTkLabel(
            navigation_group,
            text="PACKET PAGE",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=PALETTE["text_label"],
            width=92,
            anchor="w",
        ).grid(row=0, column=0, padx=4, pady=4, sticky="w")
        self.previous_page_button = ctk.CTkButton(
            navigation_group,
            text="Previous",
            width=88,
            command=self._previous_packet_page,
            state="disabled",
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["nav_hover"],
        )
        self.previous_page_button.grid(row=0, column=1, padx=4, pady=4)
        self.page_label = ctk.CTkLabel(
            navigation_group,
            text="Page 0 / 0",
            text_color=PALETTE["text_secondary"],
            anchor="w",
        )
        self.page_label.grid(row=0, column=2, padx=8, pady=4, sticky="w")
        self.next_page_button = ctk.CTkButton(
            navigation_group,
            text="Next",
            width=75,
            command=self._next_packet_page,
            state="disabled",
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["nav_hover"],
        )
        self.next_page_button.grid(row=0, column=3, padx=4, pady=4)
        self.page_size_menu = ctk.CTkOptionMenu(
            navigation_group,
            values=["100", "200", "500", "1000"],
            command=self._change_page_size,
            width=100,
        )
        self.page_size_menu.set("200")
        self.page_size_menu.grid(row=0, column=4, padx=4, pady=4)

        self.packet_label = ctk.CTkLabel(
            self.content,
            text="No capture loaded.",
            anchor="w",
            text_color=PALETTE["text_secondary"],
        )
        self.packet_label.grid(row=2, column=0, padx=10, pady=(0, 4), sticky="ew")

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Shaheen.Treeview",
            background=PALETTE["bg_table"],
            fieldbackground=PALETTE["bg_table"],
            foreground="#E2E8F0",
            rowheight=29,
            font=("Segoe UI", 10),
            borderwidth=0,
            bordercolor="#26364D",
            lightcolor="#0F172A",
        )
        style.configure(
            "Shaheen.Treeview.Heading",
            background="#1E293B",
            foreground="#F8FAFC",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
        )
        style.map(
            "Shaheen.Treeview",
            background=[("selected", "#1D4ED8")],
            foreground=[("selected", "#FFFFFF")],
        )
        style.map(
            "Shaheen.Treeview.Heading",
            background=[("active", "#334155")],
        )
        style.configure("Shaheen.TPanedwindow", background="#0B1220")

        self.workspace = ttk.Panedwindow(
            self.content,
            orient="vertical",
            style="Shaheen.TPanedwindow",
        )
        self.workspace.grid(row=3, column=0, sticky="nsew", padx=8, pady=(0, 8))

        self.packet_table_container = ctk.CTkFrame(
            self.workspace,
            fg_color=PALETTE["bg_panel"],
            corner_radius=6,
        )
        self.packet_table_container.grid_rowconfigure(0, weight=1)
        self.packet_table_container.grid_columnconfigure(0, weight=1)
        columns = ("number", "time", "source", "destination", "protocol", "length", "info")
        self.packet_table = ttk.Treeview(
            self.packet_table_container,
            columns=columns,
            show="headings",
            selectmode="browse",
            style="Shaheen.Treeview",
        )
        headings = {
            "number": ("No.", 68, "e"),
            "time": ("Time", 185, "w"),
            "source": ("Source", 155, "w"),
            "destination": ("Destination", 155, "w"),
            "protocol": ("Protocol", 95, "w"),
            "length": ("Length", 78, "e"),
            "info": ("Info", 330, "w"),
        }
        for column, (heading, width, anchor) in headings.items():
            self.packet_table.heading(column, text=heading, anchor=anchor)
            self.packet_table.column(
                column,
                width=width,
                minwidth=54 if column != "info" else 140,
                anchor=anchor,
                stretch=column in {"time", "source", "destination", "info"},
            )
        self.packet_table.grid(row=0, column=0, sticky="nsew")
        table_y_scroll = _AutoScrollbar(
            self.packet_table_container,
            orient="vertical",
            command=self.packet_table.yview,
        )
        table_y_scroll.grid(row=0, column=1, sticky="ns")
        table_x_scroll = _AutoScrollbar(
            self.packet_table_container,
            orient="horizontal",
            command=self.packet_table.xview,
        )
        table_x_scroll.grid(row=1, column=0, sticky="ew")
        self.packet_table.configure(
            yscrollcommand=table_y_scroll.set,
            xscrollcommand=table_x_scroll.set,
        )
        self.packet_empty_label = ctk.CTkLabel(
            self.packet_table_container,
            text="No capture loaded. Import a PCAP/PCAPNG or start a live capture.",
            justify="center",
            text_color=PALETTE["text_label"],
            fg_color=PALETTE["bg_panel"],
            font=ctk.CTkFont(size=14),
        )
        self.packet_empty_label.place(relx=0.5, rely=0.55, anchor="center")
        self._packet_by_iid: dict[str, PacketRecord] = {}
        self.packet_table.bind("<<TreeviewSelect>>", self._on_packet_table_select)

        details_frame = ctk.CTkFrame(self.workspace, fg_color=PALETTE["bg_panel"], corner_radius=6)
        details_frame.grid_rowconfigure(1, weight=1)
        details_frame.grid_columnconfigure(0, weight=1)
        self.details_label = ctk.CTkLabel(
            details_frame,
            text="Packet details",
            anchor="w",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#E2E8F0",
        )
        self.details_label.grid(row=0, column=0, padx=10, pady=(7, 2), sticky="ew")
        self.packet_details = ctk.CTkTextbox(
            details_frame,
            wrap="none",
            font=("Consolas", 10),
            fg_color="#0B1220",
            text_color=PALETTE["text_secondary"],
        )
        self.packet_details.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")

        hex_frame = ctk.CTkFrame(self.workspace, fg_color=PALETTE["bg_panel"], corner_radius=6)
        hex_frame.grid_rowconfigure(1, weight=1)
        hex_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hex_frame,
            text="Packet bytes · Hex / ASCII",
            anchor="w",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#E2E8F0",
        ).grid(row=0, column=0, padx=10, pady=(7, 2), sticky="ew")
        self.packet_hex = ctk.CTkTextbox(
            hex_frame,
            wrap="none",
            font=("Consolas", 10),
            fg_color="#0B1220",
            text_color=PALETTE["text_secondary"],
        )
        self.packet_hex.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")
        self.packet_details.insert("end", "Select a packet to inspect decoded fields.")
        self.packet_hex.insert("end", "Select a packet to inspect its captured bytes.")
        self.workspace.add(self.packet_table_container, weight=5)
        self.workspace.add(details_frame, weight=3)
        self.workspace.add(hex_frame, weight=2)

        self.investigation_bar = ctk.CTkFrame(
            self.content,
            fg_color=PALETTE["bg_panel"],
            border_width=1,
            border_color=PALETTE["border"],
        )
        self.investigation_bar.grid(row=4, column=0, padx=8, pady=(0, 6), sticky="ew")
        self.investigation_bar.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            self.investigation_bar,
            text="INVESTIGATION",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=PALETTE["text_label"],
        ).grid(row=0, column=0, columnspan=5, padx=8, pady=(5, 0), sticky="w")
        self.case_title_entry = ctk.CTkEntry(
            self.investigation_bar,
            placeholder_text="Investigation title",
            height=32,
        )
        self.case_title_entry.grid(row=1, column=0, padx=6, pady=5, sticky="ew")
        ctk.CTkButton(
            self.investigation_bar,
            text="Create",
            width=92,
            command=self._create_investigation,
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["nav_hover"],
        ).grid(row=1, column=1, padx=4, pady=5)
        ctk.CTkButton(
            self.investigation_bar,
            text="Add packet",
            width=104,
            command=self._add_selected_packet_to_case,
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["nav_hover"],
        ).grid(row=1, column=2, padx=4, pady=5)
        ctk.CTkButton(
            self.investigation_bar,
            text="Packets CSV",
            width=104,
            command=self._export_packets_csv,
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["nav_hover"],
        ).grid(row=1, column=3, padx=4, pady=5)
        ctk.CTkButton(
            self.investigation_bar,
            text="Export timeline",
            width=120,
            command=self._export_investigation,
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["nav_hover"],
        ).grid(row=1, column=4, padx=4, pady=5)
        self.investigation_label = ctk.CTkLabel(
            self.investigation_bar,
            text="No active investigation",
            anchor="w",
            text_color=PALETTE["text_label"],
        )
        self.investigation_label.grid(row=2, column=0, columnspan=5, padx=8, pady=(0, 5), sticky="w")

        self.status_frame = ctk.CTkFrame(self, fg_color="#080E1D", corner_radius=0, height=28)
        self.status_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.status_frame.grid_propagate(False)
        self.status_frame.grid_columnconfigure(0, weight=1)
        self.status_bar = ctk.CTkLabel(
            self.status_frame,
            text="Capture: idle",
            anchor="w",
            text_color=PALETTE["text_label"],
            font=ctk.CTkFont(size=9),
        )
        self.status_bar.grid(row=0, column=0, padx=16, sticky="ew")
        self.status_detail_bar = ctk.CTkLabel(
            self.status_frame,
            text="",
            height=0,
            anchor="w",
            text_color=PALETTE["text_label"],
            font=ctk.CTkFont(size=9),
        )
        self.status_detail_bar.grid_remove()
        self._update_table_empty_state()
        self._update_status_bar("idle")
        self.after(150, self._initialize_workspace_sashes)

        self._build_navigation_workspaces()
        self.after(200, self._poll_capture_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._refresh_interfaces()
        self._update_capture_controls()

    def _select_navigation(self, name: str) -> None:
        self._update_nav_active_state(name)
        if name == "Packet Analyzer":
            self._show_navigation_page(name)
            self.filter_entry.focus_set()
        elif name == "Live Capture":
            self._show_navigation_page(name)
            self.interface_menu.focus_set()
            try:
                values = self.interface_menu.cget("values")
                if not values or len(values) <= 1:
                    self._refresh_interfaces()
            except Exception:
                self.app.logger.exception("Could not refresh interfaces on Live Capture view")
            self.packet_label.configure(
                text="Choose an interface, then start capture. Discovery does not confirm Npcap availability."
            )
            if not self._live_capture_active:
                try:
                    self._update_page_controls()
                except Exception:
                    self.app.logger.exception("Could not update page controls for Live Capture view")
        elif name in self._navigation_pages:
            self._show_navigation_page(name)
            if name == "Dashboard":
                self._refresh_dashboard()
            elif name == "Alerts":
                self._refresh_alerts()
            elif name == "Settings":
                self._load_settings_form()
        else:
            self.packet_label.configure(
                text=f"The {name} workspace is not available in this build; packet analysis and capture controls remain available."
            )

    def _update_nav_active_state(self, active_name: str) -> None:
        if not hasattr(self, "_nav_buttons"):
            return
        for name, btn in self._nav_buttons.items():
            if name == active_name:
                btn.configure(
                    fg_color=PALETTE["primary"],
                    hover_color=PALETTE["primary_hover"] if "primary_hover" in PALETTE else "#2563EB",
                    text_color=PALETTE["text_primary"],
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    hover_color=PALETTE["nav_hover"] if "nav_hover" in PALETTE else "#1E293B",
                    text_color=PALETTE["text_label"],
                )
        self._current_nav = active_name

    def _build_navigation_workspaces(self) -> None:
        self._navigation_pages: dict[str, ctk.CTkFrame] = {}
        self._alert_events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._capture_stop_events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._alert_analysis_active = False
        self._capture_stop_pending = False
        self._capture_stop_result_received = False
        self._capture_stop_failed = False
        self._alert_rows: dict[int, sqlite3.Row] = {}

        def page(name: str) -> ctk.CTkFrame:
            frame = ctk.CTkFrame(self.content, fg_color=PALETTE["bg_panel"])
            frame.grid(row=3, column=0, sticky="nsew", padx=8, pady=(0, 8))
            frame.grid_remove()
            self._navigation_pages[name] = frame
            return frame

        dashboard = page("Dashboard")
        dashboard.grid_columnconfigure((0, 1, 2), weight=1)
        dashboard.grid_rowconfigure((2, 3, 4), weight=1)

        header_bar = ctk.CTkFrame(dashboard, fg_color="transparent")
        header_bar.grid(row=0, column=0, columnspan=3, sticky="ew", padx=24, pady=(24, 12))
        header_bar.grid_columnconfigure(0, weight=1)
        title_box = ctk.CTkFrame(header_bar, fg_color="transparent")
        title_box.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            title_box,
            text="Dashboard",
            text_color=PALETTE["text_primary"],
            font=ctk.CTkFont(size=30, weight="bold"),
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_box,
            text="Real-Time Network Security Monitoring",
            text_color=PALETTE["text_label"],
            font=ctk.CTkFont(size=12),
            anchor="w",
        ).pack(anchor="w", pady=(4, 0))

        controls = ctk.CTkFrame(header_bar, fg_color="transparent")
        controls.grid(row=0, column=1, sticky="e")
        self.dashboard_status_badge = ctk.CTkLabel(
            controls,
            text="IDLE",
            text_color=PALETTE["text_label"],
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self.dashboard_status_badge.pack(side="left", padx=(0, 12))
        self.dashboard_interface_label = ctk.CTkLabel(
            controls,
            text="Interface: -",
            text_color=PALETTE["text_label"],
            font=ctk.CTkFont(size=11),
        )
        self.dashboard_interface_label.pack(side="left", padx=(0, 12))
        self.dashboard_last_update = ctk.CTkLabel(
            controls,
            text="Last updated: -",
            text_color=PALETTE["text_label"],
            font=ctk.CTkFont(size=11),
        )
        self.dashboard_last_update.pack(side="left", padx=(0, 12))
        ctk.CTkButton(
            controls,
            text="Refresh",
            command=self._refresh_dashboard,
            height=32,
            width=90,
            corner_radius=6,
            fg_color=PALETTE["primary"],
            hover_color=PALETTE["primary_hover"],
            font=ctk.CTkFont(size=11),
        ).pack(side="left")

        # KPI cards
        kpi_frame = ctk.CTkFrame(dashboard, fg_color="transparent")
        kpi_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=24, pady=(0, 16))
        for i in range(6):
            kpi_frame.grid_columnconfigure(i, weight=1)

        def make_kpi(col, title, value_id, sub_id, color):
            card = ctk.CTkFrame(kpi_frame, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
            card.grid(row=0, column=col, padx=6, pady=0, sticky="nsew")
            card.grid_columnconfigure(0, weight=1)
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 6))
            top.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(top, text=title, text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11)).grid(row=0, column=0, sticky="w")
            setattr(self, value_id, ctk.CTkLabel(card, text="0", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=28, weight="bold"), anchor="w"))
            getattr(self, value_id).grid(row=1, column=0, sticky="w", padx=16)
            setattr(self, sub_id, ctk.CTkLabel(card, text="-", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10), anchor="w"))
            getattr(self, sub_id).grid(row=2, column=0, sticky="w", padx=16, pady=(0, 14))
            return card

        make_kpi(0, "TOTAL PACKETS", "kpi_packets", "kpi_packets_sub", PALETTE["primary"])
        make_kpi(1, "PERSISTED PACKETS", "kpi_persisted", "kpi_persisted_sub", "#06B6D4")
        make_kpi(2, "SECURITY ALERTS", "kpi_alerts", "kpi_alerts_sub", PALETTE["warning"])
        make_kpi(3, "CRITICAL ALERTS", "kpi_critical", "kpi_critical_sub", PALETTE["danger"])
        make_kpi(4, "UNIQUE HOSTS", "kpi_hosts", "kpi_hosts_sub", "#8B5CF6")
        make_kpi(5, "NETWORK TRAFFIC", "kpi_traffic", "kpi_traffic_sub", PALETTE["success"])

        # Traffic overview
        traffic_card = ctk.CTkFrame(dashboard, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        traffic_card.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=(24, 8), pady=(0, 12))
        traffic_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(traffic_card, text="NETWORK TRAFFIC OVERVIEW", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=13, weight="bold"), anchor="w").grid(row=0, column=0, sticky="w", padx=18, pady=(14, 4))
        ctk.CTkLabel(traffic_card, text="Real-time packet volume", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10), anchor="w").grid(row=1, column=0, sticky="w", padx=18)
        self.dashboard_traffic_text = ctk.CTkLabel(traffic_card, text="No network traffic data available. Start a capture or import a PCAP file.", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11), anchor="w")
        self.dashboard_traffic_text.grid(row=2, column=0, sticky="ew", padx=18, pady=(18, 18))

        # Protocol distribution
        proto_card = ctk.CTkFrame(dashboard, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        proto_card.grid(row=2, column=2, sticky="nsew", padx=(8, 24), pady=(0, 12))
        proto_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(proto_card, text="PROTOCOL DISTRIBUTION", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=13, weight="bold"), anchor="w").grid(row=0, column=0, sticky="w", padx=18, pady=(14, 4))
        self.dashboard_protocol_text = ctk.CTkLabel(proto_card, text="No protocol data available.", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11), anchor="nw", justify="left")
        self.dashboard_protocol_text.grid(row=1, column=0, sticky="ew", padx=18, pady=(12, 18))

        # Top IPs
        top_src_card = ctk.CTkFrame(dashboard, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        top_src_card.grid(row=3, column=0, sticky="nsew", padx=(24, 8), pady=(0, 12))
        top_src_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top_src_card, text="TOP SOURCE IP ADDRESSES", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=12, weight="bold"), anchor="w").grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))
        self.dashboard_top_src = ctk.CTkLabel(top_src_card, text="No data", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10), anchor="nw", justify="left")
        self.dashboard_top_src.grid(row=1, column=0, sticky="ew", padx=16, pady=(4, 12))

        top_dst_card = ctk.CTkFrame(dashboard, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        top_dst_card.grid(row=3, column=1, sticky="nsew", padx=(8, 8), pady=(0, 12))
        top_dst_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top_dst_card, text="TOP DESTINATION IP ADDRESSES", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=12, weight="bold"), anchor="w").grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))
        self.dashboard_top_dst = ctk.CTkLabel(top_dst_card, text="No data", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10), anchor="nw", justify="left")
        self.dashboard_top_dst.grid(row=1, column=0, sticky="ew", padx=16, pady=(4, 12))

        alerts_card = ctk.CTkFrame(dashboard, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        alerts_card.grid(row=3, column=2, sticky="nsew", padx=(8, 24), pady=(0, 12))
        alerts_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(alerts_card, text="SECURITY ALERTS", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=12, weight="bold"), anchor="w").grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))
        self.dashboard_alerts_overview = ctk.CTkLabel(alerts_card, text="No security alerts.", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10), anchor="nw", justify="left")
        self.dashboard_alerts_overview.grid(row=1, column=0, sticky="ew", padx=16, pady=(4, 12))

        # Recent activity and system health
        recent_card = ctk.CTkFrame(dashboard, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        recent_card.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=(24, 8), pady=(0, 16))
        recent_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(recent_card, text="RECENT NETWORK ACTIVITY", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=12, weight="bold"), anchor="w").grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))
        self.dashboard_recent = ctk.CTkLabel(recent_card, text="No recent activity.", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10), anchor="nw", justify="left")
        self.dashboard_recent.grid(row=1, column=0, sticky="ew", padx=16, pady=(4, 12))

        health_card = ctk.CTkFrame(dashboard, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        health_card.grid(row=4, column=2, sticky="nsew", padx=(8, 24), pady=(0, 16))
        health_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(health_card, text="SYSTEM HEALTH", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=12, weight="bold"), anchor="w").grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))
        self.dashboard_health = ctk.CTkLabel(health_card, text="", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10), anchor="nw", justify="left")
        self.dashboard_health.grid(row=1, column=0, sticky="ew", padx=16, pady=(4, 12))

        self.dashboard_summary = None
        self.dashboard_status = None
        ctk.CTkButton(
            dashboard, text="Refresh overview", command=self._refresh_dashboard,
        ).grid_remove()

        live_capture = page("Live Capture")
        live_capture.grid_columnconfigure((0, 1, 2), weight=1)
        live_capture.grid_rowconfigure(8, weight=1)

        # Header
        lc_header = ctk.CTkFrame(live_capture, fg_color="transparent")
        lc_header.grid(row=0, column=0, columnspan=3, sticky="ew", padx=24, pady=(24, 16))
        lc_header.grid_columnconfigure(0, weight=1)
        lc_title = ctk.CTkFrame(lc_header, fg_color="transparent")
        lc_title.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(lc_title, text="LIVE NETWORK CAPTURE", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(lc_title, text="Real-Time Packet Monitoring & Inspection", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11)).pack(anchor="w", pady=(4, 0))
        lc_ctrls = ctk.CTkFrame(lc_header, fg_color="transparent")
        lc_ctrls.grid(row=0, column=1, sticky="e")
        self.live_status_badge = ctk.CTkLabel(lc_ctrls, text="IDLE", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11, weight="bold"))
        self.live_status_badge.pack(side="left", padx=(0, 12))
        self.live_iface_label = ctk.CTkLabel(lc_ctrls, text="Interface: -", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11))
        self.live_iface_label.pack(side="left", padx=(0, 12))
        self.live_duration_label = ctk.CTkLabel(lc_ctrls, text="Duration: 00:00:00", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11))
        self.live_duration_label.pack(side="left")

        # Capture controls panel
        ctrl_panel = ctk.CTkFrame(live_capture, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        ctrl_panel.grid(row=1, column=0, columnspan=3, sticky="ew", padx=24, pady=(0, 12))
        ctrl_panel.grid_columnconfigure((0, 1, 2), weight=1)
        grp_a = ctk.CTkFrame(ctrl_panel, fg_color="transparent")
        grp_a.grid(row=0, column=0, sticky="nsew", padx=14, pady=12)
        ctk.CTkLabel(grp_a, text="NETWORK INTERFACE", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        ctk.CTkLabel(grp_a, text="Interface", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10)).grid(row=1, column=0, sticky="w")
        # reuse existing interface menu if exists
        if not hasattr(self, 'interface_menu'):
            self.interface_menu = ctk.CTkOptionMenu(grp_a, values=["Select interface"])
        self.interface_menu.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(2, 6))
        if not hasattr(self, 'refresh_interfaces_button'):
            self.refresh_interfaces_button = ctk.CTkButton(grp_a, text="Refresh", height=28)
        self.refresh_interfaces_button.grid(row=3, column=0, sticky="w")
        ctk.CTkButton(grp_a, text="Start Capture", command=self._start_live_capture, height=28, fg_color=PALETTE["success"], hover_color="#16A34A").grid(row=4, column=0, sticky="ew", pady=(10, 4))
        ctk.CTkButton(grp_a, text="Stop Capture", command=self._stop_live_capture, height=28, fg_color=PALETTE["danger"], hover_color=PALETTE["danger_hover"]).grid(row=5, column=0, sticky="ew", pady=4)
        ctk.CTkButton(grp_a, text="Pause Display", command=self._toggle_display_pause, height=28).grid(row=6, column=0, sticky="ew", pady=4)

        grp_b = ctk.CTkFrame(ctrl_panel, fg_color="transparent")
        grp_b.grid(row=0, column=1, sticky="nsew", padx=14, pady=12)
        ctk.CTkLabel(grp_b, text="FILE IMPORT & RECORDING", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        if not hasattr(self, 'import_button'):
            self.import_button = ctk.CTkButton(grp_b, text="Import PCAP/PCAPNG", command=self._import_file, height=28)
        self.import_button.grid(row=1, column=0, sticky="ew", pady=4)
        if not hasattr(self, 'cancel_import_button'):
            self.cancel_import_button = ctk.CTkButton(grp_b, text="Cancel Import", height=28)
        self.cancel_import_button.grid(row=2, column=0, sticky="ew", pady=4)
        if not hasattr(self, 'start_recording_button'):
            self.start_recording_button = ctk.CTkButton(grp_b, text="Start Recording", command=self._start_recording, height=28)
        self.start_recording_button.grid(row=3, column=0, sticky="ew", pady=(10, 4))
        if not hasattr(self, 'stop_recording_button'):
            self.stop_recording_button = ctk.CTkButton(grp_b, text="Stop Recording", command=self._stop_recording, height=28)
        self.stop_recording_button.grid(row=4, column=0, sticky="ew", pady=4)
        self.live_import_status = ctk.CTkLabel(grp_b, text="No import active", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=9))
        self.live_import_status.grid(row=5, column=0, sticky="w", pady=(8, 0))

        grp_c = ctk.CTkFrame(ctrl_panel, fg_color="transparent")
        grp_c.grid(row=0, column=2, sticky="nsew", padx=14, pady=12)
        ctk.CTkLabel(grp_c, text="DISPLAY FILTER", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        if not hasattr(self, 'filter_entry'):
            self.filter_entry = ctk.CTkEntry(grp_c, placeholder_text="Example: tcp.port == 443 or dns")
        self.filter_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=4)
        if not hasattr(self, 'apply_filter_button'):
            self.apply_filter_button = ctk.CTkButton(grp_c, text="Apply Filter", command=self._apply_filter, height=28)
        self.apply_filter_button.grid(row=2, column=0, sticky="ew", pady=4)
        ctk.CTkButton(grp_c, text="Clear Filter", command=self._clear_filter, height=28).grid(row=3, column=0, sticky="ew", pady=4)
        self.live_filter_status = ctk.CTkLabel(grp_c, text="No active filter", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=9))
        self.live_filter_status.grid(row=4, column=0, sticky="w", pady=(8, 0))

        # KPI cards
        kpi_frame = ctk.CTkFrame(live_capture, fg_color="transparent")
        kpi_frame.grid(row=2, column=0, columnspan=3, sticky="ew", padx=24, pady=(0, 12))
        for i in range(6): kpi_frame.grid_columnconfigure(i, weight=1)
        def mk(col, title, varv, vars):
            card = ctk.CTkFrame(kpi_frame, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
            card.grid(row=0, column=col, padx=6, sticky="nsew")
            ctk.CTkLabel(card, text=title, text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10)).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))
            setattr(self, varv, ctk.CTkLabel(card, text="0", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=22, weight="bold")))
            getattr(self, varv).grid(row=1, column=0, sticky="w", padx=14)
            setattr(self, vars, ctk.CTkLabel(card, text="-", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=9)))
            getattr(self, vars).grid(row=2, column=0, sticky="w", padx=14, pady=(2, 12))
        mk(0, "PACKETS RECEIVED", "lkpi_recv", "lkpi_recv_s")
        mk(1, "PACKETS ACCEPTED", "lkpi_acc", "lkpi_acc_s")
        mk(2, "PACKETS PERSISTED", "lkpi_pers", "lkpi_pers_s")
        mk(3, "PACKETS PER SECOND", "lkpi_pps", "lkpi_pps_s")
        mk(4, "TOTAL DATA", "lkpi_data", "lkpi_data_s")
        mk(5, "DETECTION ALERTS", "lkpi_lalerts", "lkpi_lalerts_s")

        # Traffic graph + protocol
        graph_frame = ctk.CTkFrame(live_capture, fg_color="transparent")
        graph_frame.grid(row=3, column=0, columnspan=3, sticky="ew", padx=24, pady=(0, 12))
        graph_frame.grid_columnconfigure((0,1), weight=1)
        g1 = ctk.CTkFrame(graph_frame, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        g1.grid(row=0, column=0, sticky="nsew", padx=(0,8))
        ctk.CTkLabel(g1, text="LIVE TRAFFIC ANALYTICS", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))
        self.live_traffic_graph = ctk.CTkLabel(g1, text="No capture active. Start capture to view live traffic.", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11))
        self.live_traffic_graph.grid(row=1, column=0, sticky="ew", padx=16, pady=(10, 16))
        g2 = ctk.CTkFrame(graph_frame, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        g2.grid(row=0, column=1, sticky="nsew", padx=(8,0))
        ctk.CTkLabel(g2, text="PROTOCOL BREAKDOWN", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))
        self.live_proto = ctk.CTkLabel(g2, text="No protocol data available.", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11), justify="left")
        self.live_proto.grid(row=1, column=0, sticky="ew", padx=16, pady=(10, 16))

        # Packet stream
        pkt_frame = ctk.CTkFrame(live_capture, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        pkt_frame.grid(row=4, column=0, columnspan=3, sticky="nsew", padx=24, pady=(0, 12))
        pkt_frame.grid_columnconfigure(0, weight=1)
        pkt_frame.grid_rowconfigure(2, weight=1)
        pf_h = ctk.CTkFrame(pkt_frame, fg_color="transparent")
        pf_h.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 6))
        pf_h.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(pf_h, text="LIVE PACKET STREAM", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, sticky="w")
        pkt_table_frame = ttk.Frame(pkt_frame)
        pkt_table_frame.grid(row=1, column=0, sticky="nsew", padx=16)
        pkt_table_frame.grid_columnconfigure(0, weight=1)
        pkt_table_frame.grid_rowconfigure(0, weight=1)
        # reuse packet tree if exists
        if not hasattr(self, 'packet_tree'):
            self.packet_tree = ttk.Treeview(pkt_table_frame, columns=("no","time","src_ip","src_port","dst_ip","dst_port","proto","len","flags","info"), show="headings", height=10)
        cols = [("no","#"),("time","Time"),("src_ip","Source IP"),("src_port","Src Port"),("dst_ip","Dest IP"),("dst_port","Dst Port"),("proto","Proto"),("len","Length"),("flags","Flags"),("info","Info")]
        for c,h in cols:
            self.packet_tree.heading(c,text=h)
            self.packet_tree.column(c,width=90)
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        pscroll = ttk.Scrollbar(pkt_table_frame, orient="vertical", command=self.packet_tree.yview)
        pscroll.grid(row=0, column=1, sticky="ns")
        self.packet_tree.configure(yscrollcommand=pscroll.set)
        try:
            self.packet_tree.bind("<<TreeviewSelect>>", self._on_packet_select)
        except Exception:
            self.packet_tree.bind("<<TreeviewSelect>>", lambda e: self._on_packet_tree_select())

        # Details
        det_frame = ctk.CTkFrame(live_capture, fg_color="transparent")
        det_frame.grid(row=5, column=0, columnspan=3, sticky="nsew", padx=24, pady=(0, 16))
        det_frame.grid_columnconfigure((0,1,2), weight=1)
        det1 = ctk.CTkFrame(det_frame, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        det1.grid(row=0, column=0, sticky="nsew", padx=(0,6))
        ctk.CTkLabel(det1, text="PACKET DETAILS", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 4))
        if not hasattr(self, 'packet_details'):
            self.packet_details = ctk.CTkTextbox(det1, height=160)
        self.packet_details.grid(row=1, column=0, sticky="nsew", padx=14, pady=(4, 12))
        det2 = ctk.CTkFrame(det_frame, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        det2.grid(row=0, column=1, sticky="nsew", padx=6)
        ctk.CTkLabel(det2, text="HEX VIEW", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 4))
        if not hasattr(self, 'packet_hex'):
            self.packet_hex = ctk.CTkTextbox(det2, height=160)
        self.packet_hex.grid(row=1, column=0, sticky="nsew", padx=14, pady=(4, 12))
        det3 = ctk.CTkFrame(det_frame, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        det3.grid(row=0, column=2, sticky="nsew", padx=(6,0))
        ctk.CTkLabel(det3, text="PROTOCOL STACK", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 4))
        if not hasattr(self, 'packet_protocol_stack'):
            self.packet_protocol_stack = ctk.CTkTextbox(det3, height=160)
        self.packet_protocol_stack.grid(row=1, column=0, sticky="nsew", padx=14, pady=(4, 12))

        # ensure packet_label hidden for this page
        self.live_capture_info = None
        self.packet_label.configure(text="")

        alerts = page("Alerts")
        alerts.grid_columnconfigure(0, weight=1)
        alerts.grid_rowconfigure(2, weight=1)
        ctk.CTkLabel(
            alerts,
            text="Detection alerts",
            font=ctk.CTkFont(size=20, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=12, pady=(12, 4), sticky="ew")
        filters = ctk.CTkFrame(alerts, fg_color="transparent")
        filters.grid(row=1, column=0, padx=8, pady=4, sticky="ew")
        for column in range(7):
            filters.grid_columnconfigure(column, weight=1 if column in {2, 3} else 0)
        self.alert_severity_filter = ctk.CTkOptionMenu(
            filters, values=["All", "low", "medium", "high", "critical"], width=110,
            command=lambda _value: self._refresh_alerts(),
        )
        self.alert_severity_filter.set("All")
        self.alert_severity_filter.grid(row=0, column=0, padx=3, pady=3)
        self.alert_status_filter = ctk.CTkOptionMenu(
            filters, values=["All", "new", "acknowledged", "resolved"], width=130,
            command=lambda _value: self._refresh_alerts(),
        )
        self.alert_status_filter.set("All")
        self.alert_status_filter.grid(row=0, column=1, padx=3, pady=3)
        self.alert_source_filter = ctk.CTkEntry(filters, placeholder_text="Source")
        self.alert_source_filter.grid(row=0, column=2, padx=3, pady=3, sticky="ew")
        self.alert_destination_filter = ctk.CTkEntry(filters, placeholder_text="Destination")
        self.alert_destination_filter.grid(row=0, column=3, padx=3, pady=3, sticky="ew")
        self.alert_start_date_filter = ctk.CTkEntry(
            filters, placeholder_text="From date (YYYY-MM-DD)", width=150,
        )
        self.alert_start_date_filter.grid(row=0, column=4, padx=3, pady=3)
        self.alert_end_date_filter = ctk.CTkEntry(
            filters, placeholder_text="To date (YYYY-MM-DD)", width=150,
        )
        self.alert_end_date_filter.grid(row=0, column=5, padx=3, pady=3)
        ctk.CTkButton(
            filters, text="Refresh", width=80, command=self._refresh_alerts,
        ).grid(row=0, column=6, padx=3, pady=3)

        alert_body = ttk.Frame(alerts)
        alert_body.grid(row=2, column=0, padx=10, pady=6, sticky="nsew")
        alert_body.grid_columnconfigure(0, weight=3)
        alert_body.grid_columnconfigure(2, weight=2)
        alert_body.grid_rowconfigure(0, weight=1)
        self.alert_table = ttk.Treeview(
            alert_body,
            columns=("time", "severity", "rule", "source", "destination", "status"),
            show="headings",
            selectmode="browse",
            height=12,
        )
        for column, heading in (
            ("time", "Timestamp"),
            ("severity", "Severity"),
            ("rule", "Rule"),
            ("source", "Source"),
            ("destination", "Destination"),
            ("status", "Status"),
        ):
            self.alert_table.heading(column, text=heading)
            self.alert_table.column(column, width=120, anchor="w")
        self.alert_table.grid(row=0, column=0, sticky="nsew")
        alert_scrollbar = ttk.Scrollbar(
            alert_body, orient="vertical", command=self.alert_table.yview,
        )
        alert_scrollbar.grid(row=0, column=1, sticky="ns")
        self.alert_table.configure(yscrollcommand=alert_scrollbar.set)
        self.alert_table.bind("<<TreeviewSelect>>", self._show_alert_details)
        self.alert_table.bind("<Double-1>", lambda _event: self._open_alert_evidence())
        self.alert_details = ctk.CTkTextbox(alert_body, wrap="word")
        self.alert_details.grid(row=0, column=2, padx=(8, 0), sticky="nsew")
        alert_actions = ctk.CTkFrame(alerts, fg_color="transparent")
        alert_actions.grid(row=3, column=0, padx=8, pady=(4, 8), sticky="ew")
        self.alert_status_message = ctk.CTkLabel(
            alert_actions, text="No alert analysis has been run for this session.",
            anchor="w",
        )
        self.alert_status_message.grid(row=0, column=0, padx=4, sticky="ew")
        alert_actions.grid_columnconfigure(0, weight=1)
        self.analyze_alerts_button = ctk.CTkButton(
            alert_actions,
            text="Analyze current session",
            command=self._analyze_current_session,
            width=170,
        )
        self.analyze_alerts_button.grid(row=0, column=1, padx=3)
        ctk.CTkButton(
            alert_actions, text="Open evidence packet",
            command=self._open_alert_evidence, width=150,
        ).grid(row=0, column=2, padx=3)
        ctk.CTkButton(
            alert_actions, text="Acknowledge", width=105,
            command=lambda: self._set_selected_alert_status("acknowledged"),
        ).grid(row=0, column=3, padx=3)
        ctk.CTkButton(
            alert_actions, text="Resolve", width=85,
            command=lambda: self._set_selected_alert_status("resolved"),
        ).grid(row=0, column=4, padx=3)

        reports = page("Reports")
        reports.grid_columnconfigure((0,1,2), weight=1)
        reports.grid_rowconfigure(4, weight=1)

        # Header
        rep_h = ctk.CTkFrame(reports, fg_color="transparent")
        rep_h.grid(row=0, column=0, columnspan=3, sticky="ew", padx=24, pady=(24, 12))
        rep_h.grid_columnconfigure(0, weight=1)
        rep_t = ctk.CTkFrame(rep_h, fg_color="transparent")
        rep_t.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(rep_t, text="SECURITY REPORTS", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(rep_t, text="Network Intelligence, Threat Analysis & Forensic Documentation", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11)).pack(anchor="w", pady=(4,0))
        rep_c = ctk.CTkFrame(rep_h, fg_color="transparent")
        rep_c.grid(row=0, column=1, sticky="e")
        try:
            ctk.CTkButton(rep_c, text="Refresh", command=self._refresh_reports, height=32, width=90).pack(side="left", padx=6)
        except Exception:
            def _r():
                try:
                    self._refresh_reports()
                except Exception:
                    pass
            ctk.CTkButton(rep_c, text="Refresh", command=_r, height=32, width=90).pack(side="left", padx=6)
        ctk.CTkButton(rep_c, text="Generate New Report", height=32, width=150, fg_color=PALETTE["primary"], hover_color=PALETTE["primary_hover"]).pack(side="left")

        # KPI
        rkpi = ctk.CTkFrame(reports, fg_color="transparent")
        rkpi.grid(row=1, column=0, columnspan=3, sticky="ew", padx=24, pady=(0,12))
        for i in range(6): rkpi.grid_columnconfigure(i, weight=1)
        def rm(col,title,v,vs):
            card = ctk.CTkFrame(rkpi, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
            card.grid(row=0,column=col,padx=6,sticky="nsew")
            ctk.CTkLabel(card,text=title,text_color=PALETTE["text_label"],font=ctk.CTkFont(size=10)).grid(row=0,column=0,sticky="w",padx=14,pady=(12,4))
            setattr(self,v,ctk.CTkLabel(card,text="0",text_color=PALETTE["text_primary"],font=ctk.CTkFont(size=22,weight="bold")))
            getattr(self,v).grid(row=1,column=0,sticky="w",padx=14)
            setattr(self,vs,ctk.CTkLabel(card,text="-",text_color=PALETTE["text_label"],font=ctk.CTkFont(size=9)))
            getattr(self,vs).grid(row=2,column=0,sticky="w",padx=14,pady=(2,12))
        rm(0,"TOTAL CAPTURE SESSIONS","rkpi_sess","rkpi_sess_s")
        rm(1,"TOTAL PACKETS","rkpi_pkt","rkpi_pkt_s")
        rm(2,"SECURITY ALERTS","rkpi_alt","rkpi_alt_s")
        rm(3,"CRITICAL EVENTS","rkpi_crit","rkpi_crit_s")
        rm(4,"INVESTIGATIONS","rkpi_inv","rkpi_inv_s")
        rm(5,"GENERATED REPORTS","rkpi_rep","rkpi_rep_s")

        # Generate workspace
        gen = ctk.CTkFrame(reports, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        gen.grid(row=2, column=0, columnspan=3, sticky="ew", padx=24, pady=(0,12))
        gen.grid_columnconfigure((0,1,2), weight=1)
        ctk.CTkLabel(gen, text="GENERATE SECURITY REPORT", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=13, weight="bold")).grid(row=0,column=0,columnspan=3,sticky="w",padx=18,pady=(14,8))
        ctk.CTkLabel(gen, text="Report Type", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10)).grid(row=1,column=0,sticky="w",padx=18)
        self.report_type_menu = ctk.CTkOptionMenu(gen, values=["Network Traffic Analysis Report","Packet Capture Summary","Security Threat Detection Report","Alert Analysis Report","Investigation Timeline Report","Comprehensive SOC Report"], width=260)
        self.report_type_menu.grid(row=2,column=0,sticky="w",padx=18,pady=(2,10))
        ctk.CTkLabel(gen, text="Format", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10)).grid(row=1,column=1,sticky="w",padx=18)
        self.report_format_menu = ctk.CTkOptionMenu(gen, values=["PDF","CSV","JSON","HTML"], width=140)
        self.report_format_menu.grid(row=2,column=1,sticky="w",padx=18,pady=(2,10))
        try:
            ctk.CTkButton(gen, text="Generate Report", command=self._generate_comprehensive_report, height=32, fg_color=PALETTE["primary"], hover_color=PALETTE["primary_hover"]).grid(row=2,column=2,sticky="e",padx=18,pady=(2,10))
        except Exception:
            def _g():
                try:
                    self._generate_comprehensive_report()
                except Exception:
                    pass
            ctk.CTkButton(gen, text="Generate Report", command=_g, height=32, fg_color=PALETTE["primary"], hover_color=PALETTE["primary_hover"]).grid(row=2,column=2,sticky="e",padx=18,pady=(2,10))
        ctk.CTkButton(gen, text="Export Current Session Packets (CSV)", command=self._export_packets_csv, height=28).grid(row=3,column=0,sticky="w",padx=18,pady=(0,12))
        ctk.CTkButton(gen, text="Export Active Investigation Timeline", command=self._export_investigation, height=28).grid(row=3,column=1,sticky="w",padx=18,pady=(0,12))
        ctk.CTkLabel(gen, text=f"Report Directory: {self.app.settings.report_path}", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10)).grid(row=4,column=0,columnspan=3,sticky="w",padx=18,pady=(0,14))

        # History
        hist = ctk.CTkFrame(reports, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        hist.grid(row=3, column=0, columnspan=3, sticky="nsew", padx=24, pady=(0,16))
        hist.grid_columnconfigure(0, weight=1)
        hist.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(hist, text="GENERATED REPORTS", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=13, weight="bold")).grid(row=0,column=0,sticky="w",padx=18,pady=(14,8))
        rep_tbl_frame = ttk.Frame(hist)
        rep_tbl_frame.grid(row=1,column=0,sticky="nsew",padx=18,pady=(0,14))
        rep_tbl_frame.grid_columnconfigure(0, weight=1)
        rep_tbl_frame.grid_rowconfigure(0, weight=1)
        self.report_history_table = ttk.Treeview(rep_tbl_frame, columns=("id","name","type","date","period","format","size","status"), show="headings", height=8)
        for c,h,w in [("id","Report ID",80),("name","Report Name",200),("type","Report Type",200),("date","Generated Date",150),("period","Reporting Period",150),("format","Format",80),("size","File Size",90),("status","Status",90)]:
            self.report_history_table.heading(c,text=h)
            self.report_history_table.column(c,width=w)
        self.report_history_table.grid(row=0,column=0,sticky="nsew")
        rscroll = ttk.Scrollbar(rep_tbl_frame, orient="vertical", command=self.report_history_table.yview)
        rscroll.grid(row=0,column=1,sticky="ns")
        self.report_history_table.configure(yscrollcommand=rscroll.set)

        try:
            self._load_report_history()
        except Exception:
            pass
        try:
            self.after(100, self._refresh_reports)
        except Exception:
            pass

        settings = page("Settings")
        settings.grid_columnconfigure(1, weight=1)
        settings.grid_rowconfigure(2, weight=1)

        # Header
        st_h = ctk.CTkFrame(settings, fg_color="transparent")
        st_h.grid(row=0, column=0, columnspan=2, sticky="ew", padx=24, pady=(24, 12))
        st_h.grid_columnconfigure(0, weight=1)
        st_t = ctk.CTkFrame(st_h, fg_color="transparent")
        st_t.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(st_t, text="SYSTEM SETTINGS", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(st_t, text="Configure, monitor and manage SHAHEEN application services.", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11)).pack(anchor="w", pady=(4,0))
        st_c = ctk.CTkFrame(st_h, fg_color="transparent")
        st_c.grid(row=0, column=1, sticky="e")
        try:
            ctk.CTkButton(st_c, text="Save all settings", command=self._save_settings_form, height=32, fg_color=PALETTE["primary"], hover_color=PALETTE["primary_hover"]).pack(side="left", padx=6)
        except Exception:
            def _ss(): 
                try: self._save_settings_form()
                except Exception: pass
            ctk.CTkButton(st_c, text="Save all settings", command=_ss, height=32, fg_color=PALETTE["primary"], hover_color=PALETTE["primary_hover"]).pack(side="left", padx=6)
        try:
            ctk.CTkButton(st_c, text="Reset to defaults", command=self._reset_settings_defaults, height=32).pack(side="left")
        except Exception:
            def _rd():
                try: self._reset_settings_defaults()
                except Exception: pass
            ctk.CTkButton(st_c, text="Reset to defaults", command=_rd, height=32).pack(side="left")

        # Nav
        nav_frame = ctk.CTkFrame(settings, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"], width=240)
        nav_frame.grid(row=1, column=0, sticky="ns", padx=(24,12), pady=(0,16))
        nav_frame.grid_propagate(False)
        nav_frame.grid_rowconfigure(12, weight=1)
        ctk.CTkLabel(nav_frame, text="CATEGORIES", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10, weight="bold")).grid(row=0, column=0, sticky="w", padx=16, pady=(14,10))
        cats = ["General", "Network Capture", "Packet Analysis", "Performance", "Storage & Database", "Reports & Exports", "Alerts & Detection", "Logging & Diagnostics", "Privacy & Security", "About SHAHEEN"]
        self._settings_nav = {}
        for i,c in enumerate(cats):
            b = ctk.CTkButton(nav_frame, text="  " + c, anchor="w", height=36, fg_color="transparent", hover_color=PALETTE["nav_hover"], text_color=PALETTE["text_label"], command=lambda name=c: self._select_settings_category(name))
            b.grid(row=i+1, column=0, sticky="ew", padx=10, pady=2)
            self._settings_nav[c] = b
        if cats:
            try:
                self._select_settings_category(cats[0])
            except Exception:
                pass

        # Content area
        self.settings_content = ctk.CTkScrollableFrame(settings, fg_color=PALETTE["bg_card"], corner_radius=10, border_width=1, border_color=PALETTE["border"])
        self.settings_content.grid(row=1, column=1, sticky="nsew", padx=(0,24), pady=(0,16))
        self.settings_content.grid_columnconfigure(0, weight=1)
        self._settings_pages = {}
        try:
            self._build_settings_ui_fixed()
        except Exception:
            try:
                self._build_settings_ui()
            except Exception:
                try:
                    self._load_settings_form()
                except Exception:
                    pass

        self.settings_status = ctk.CTkLabel(
            settings, text="", anchor="w", text_color=PALETTE["text_label"], font=ctk.CTkFont(size=10),
        )
        self.settings_status.grid(row=2, column=0, columnspan=2, padx=24, pady=(0,12), sticky="ew")
        self.after(200, self._poll_alert_events)
        self.after(200, self._poll_capture_stop_events)

    def _show_navigation_page(self, name: str) -> None:
        try:
            self._update_nav_active_state(name)
        except Exception:
            pass
        self.toolbar.grid()
        self.packet_label.grid()
        self.workspace.grid_remove()
        self.investigation_bar.grid_remove()
        for frame in self._navigation_pages.values():
            frame.grid_remove()
        if name == "Packet Analyzer":
            self.header.configure(text=name)
            self.packet_label.grid()
            self.workspace.grid()
            self.investigation_bar.grid()
            return
        self.header.configure(text=name)
        self.packet_label.grid_remove()
        page = self._navigation_pages.get(name)
        if page is not None:
            page.grid()
        if name not in {"Live Capture"}:
            self.toolbar.grid_remove()

    def _refresh_dashboard(self) -> None:
        try:
            from datetime import datetime
            session_count = self.app.db.execute(
                "SELECT COUNT(*) FROM capture_sessions"
            ).fetchone()[0]
            packet_count = self.app.db.execute(
                "SELECT COUNT(*) FROM packets"
            ).fetchone()[0]
            alert_count = self.app.db.execute(
                "SELECT COUNT(*) FROM alerts"
            ).fetchone()[0]
            critical_alerts = self.app.db.execute(
                "SELECT COUNT(*) FROM alerts WHERE LOWER(severity)='critical'"
            ).fetchone()[0]
            unresolved_critical = self.app.db.execute(
                "SELECT COUNT(*) FROM alerts WHERE LOWER(severity)='critical' AND LOWER(COALESCE(status,'')) NOT IN ('resolved','closed')"
            ).fetchone()[0]
            unique_src = self.app.db.execute(
                "SELECT COUNT(DISTINCT source_address) FROM packets WHERE source_address IS NOT NULL AND source_address != ''"
            ).fetchone()[0]
            unique_dst = self.app.db.execute(
                "SELECT COUNT(DISTINCT destination_address) FROM packets WHERE destination_address IS NOT NULL AND destination_address != ''"
            ).fetchone()[0]
            total_bytes = self.app.db.execute(
                "SELECT COALESCE(SUM(packet_length),0) FROM packets"
            ).fetchone()[0]

            # KPI updates
            if hasattr(self, 'kpi_packets'):
                self.kpi_packets.configure(text=f"{packet_count:,}")
                self.kpi_packets_sub.configure(text=f"Across {session_count} sessions")
            if hasattr(self, 'kpi_persisted'):
                self.kpi_persisted.configure(text=f"{packet_count:,}")
                self.kpi_persisted_sub.configure(text="Saved to database")
            if hasattr(self, 'kpi_alerts'):
                self.kpi_alerts.configure(text=f"{alert_count}")
                self.kpi_alerts_sub.configure(text=f"Critical: {critical_alerts}")
            if hasattr(self, 'kpi_critical'):
                self.kpi_critical.configure(text=f"{critical_alerts}")
                self.kpi_critical_sub.configure(text=f"Unresolved: {unresolved_critical}")
            if hasattr(self, 'kpi_hosts'):
                self.kpi_hosts.configure(text=f"{unique_src + unique_dst}")
                self.kpi_hosts_sub.configure(text=f"Src: {unique_src} | Dst: {unique_dst}")
            if hasattr(self, 'kpi_traffic'):
                mb = float(total_bytes or 0) / (1024*1024)
                self.kpi_traffic.configure(text=f"{mb:.2f} MB")
                self.kpi_traffic_sub.configure(text=f"{int(total_bytes or 0):,} bytes")

            # Header
            if hasattr(self, 'dashboard_status_badge'):
                if self.capture_manager.is_running:
                    self.dashboard_status_badge.configure(text="CAPTURING", text_color=PALETTE["text_success"])
                else:
                    self.dashboard_status_badge.configure(text="IDLE", text_color=PALETTE["text_label"])
            if hasattr(self, 'dashboard_interface_label'):
                label = self.interface_menu.get() if hasattr(self, 'interface_menu') else "-"
                self.dashboard_interface_label.configure(text=f"Interface: {label}")
            if hasattr(self, 'dashboard_last_update'):
                self.dashboard_last_update.configure(text=f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

            # Traffic overview
            if hasattr(self, 'dashboard_traffic_text'):
                if packet_count == 0:
                    self.dashboard_traffic_text.configure(text="No network traffic data available. Start a capture or import a PCAP file.")
                else:
                    self.dashboard_traffic_text.configure(text=f"Observed {packet_count:,} packets totaling {int(total_bytes or 0):,} bytes across stored sessions.")

            # Protocol distribution
            if hasattr(self, 'dashboard_protocol_text'):
                proto_rows = self.app.db.execute(
                    "SELECT protocol, COUNT(*) as c FROM packets WHERE protocol IS NOT NULL AND protocol != '' GROUP BY protocol ORDER BY c DESC LIMIT 6"
                ).fetchall()
                if not proto_rows:
                    self.dashboard_protocol_text.configure(text="No protocol data available.")
                else:
                    lines = []
                    for r in proto_rows:
                        lines.append(f"{r['protocol']}: {r['c']:,} packets")
                    self.dashboard_protocol_text.configure(text="\n".join(lines))

            # Top IPs
            if hasattr(self, 'dashboard_top_src'):
                rows = self.app.db.execute(
                    "SELECT source_address, COUNT(*) as c, COALESCE(SUM(packet_length),0) as b FROM packets WHERE source_address IS NOT NULL AND source_address != '' GROUP BY source_address ORDER BY c DESC LIMIT 5"
                ).fetchall()
                if not rows:
                    self.dashboard_top_src.configure(text="No data")
                else:
                    lines = ["IP                Packets      Bytes"]
                    for r in rows:
                        ip = str(r['source_address'])[:16].ljust(16)
                        lines.append(f"{ip} {int(r['c']):<12} {int(r['b']):,}")
                    self.dashboard_top_src.configure(text="\n".join(lines))
            if hasattr(self, 'dashboard_top_dst'):
                rows = self.app.db.execute(
                    "SELECT destination_address, COUNT(*) as c, COALESCE(SUM(packet_length),0) as b FROM packets WHERE destination_address IS NOT NULL AND destination_address != '' GROUP BY destination_address ORDER BY c DESC LIMIT 5"
                ).fetchall()
                if not rows:
                    self.dashboard_top_dst.configure(text="No data")
                else:
                    lines = ["IP                Packets      Bytes"]
                    for r in rows:
                        ip = str(r['destination_address'])[:16].ljust(16)
                        lines.append(f"{ip} {int(r['c']):<12} {int(r['b']):,}")
                    self.dashboard_top_dst.configure(text="\n".join(lines))

            # Alerts overview
            if hasattr(self, 'dashboard_alerts_overview'):
                arows = self.app.db.execute(
                    "SELECT severity, COUNT(*) as c FROM alerts GROUP BY severity"
                ).fetchall()
                if not arows:
                    self.dashboard_alerts_overview.configure(text="No security alerts.")
                else:
                    parts = []
                    for r in arows:
                        sev = str(r['severity'] or 'Unknown')
                        parts.append(f"{sev}: {r['c']}")
                    self.dashboard_alerts_overview.configure(text="  |  ".join(parts))

            # Recent activity
            if hasattr(self, 'dashboard_recent'):
                rrows = self.app.db.execute(
                    "SELECT timestamp, source_address, destination_address, protocol, packet_length FROM packets ORDER BY id DESC LIMIT 5"
                ).fetchall()
                if not rrows:
                    self.dashboard_recent.configure(text="No recent activity.")
                else:
                    lines = ["Time        Src              Dst              Proto  Len"]
                    for r in rrows:
                        ts = str(r['timestamp'] or '-')[:10]
                        src = str(r['source_address'] or '-')[:16].ljust(16)
                        dst = str(r['destination_address'] or '-')[:16].ljust(16)
                        proto = str(r['protocol'] or '-')[:5].ljust(5)
                        lines.append(f"{ts} {src} {dst} {proto} {r['packet_length'] or 0}")
                    self.dashboard_recent.configure(text="\n".join(lines))

            # Health
            if hasattr(self, 'dashboard_health'):
                avail, msg = self.capture_manager.capture_provider_status()
                health = f"Capture Engine: {'OK' if self.capture_manager.is_running or True else 'IDLE'}\n"
                health += f"Npcap/Libpcap: {'Available' if avail else 'Unavailable'}\n"
                health += f"Database: Connected\n"
                health += f"Status: {msg[:60]}\n"
                health += f"Interface: {self.interface_menu.get() if hasattr(self, 'interface_menu') else '-'}"
                self.dashboard_health.configure(text=health)

        except Exception as exc:
            self.app.logger.exception("Could not load Dashboard statistics")
            if hasattr(self, 'dashboard_traffic_text'):
                self.dashboard_traffic_text.configure(text=f"Dashboard data unavailable: {exc}")
            if hasattr(self, 'dashboard_health'):
                self.dashboard_health.configure(text="System health unavailable")

    def _load_settings_form(self) -> None:
        self.settings_theme.set(self.app.settings.theme)
        self.settings_capture_filter.delete(0, "end")
        self.settings_capture_filter.insert(0, self.app.settings.capture_filter)
        self.settings_report_path.delete(0, "end")
        self.settings_report_path.insert(0, self.app.settings.report_path)

    def _browse_report_directory(self) -> None:
        selected = filedialog.askdirectory(
            title="Choose report directory",
            initialdir=self.settings_report_path.get() or self.app.settings.report_path,
        )
        if selected:
            self.settings_report_path.delete(0, "end")
            self.settings_report_path.insert(0, selected)

    def _save_settings_form(self) -> None:
        try:
            values = validate_editable_settings(
                theme=self.settings_theme.get(),
                capture_filter=self.settings_capture_filter.get(),
                report_path=self.settings_report_path.get(),
            )
        except ValueError as exc:
            self.settings_status.configure(text=str(exc))
            messagebox.showerror("Shaheen settings", str(exc))
            return
        previous = {
            key: getattr(self.app.settings, key)
            for key in values
        }
        for key, value in values.items():
            setattr(self.app.settings, key, value)
        try:
            save_persisted_settings(self.app.settings, self.app.db)
        except (OSError, sqlite3.Error, ValueError) as exc:
            for key, value in previous.items():
                setattr(self.app.settings, key, value)
            self.app.logger.exception("Could not save application settings")
            self.settings_status.configure(text=f"Settings were not saved: {exc}")
            messagebox.showerror("Shaheen settings", f"Settings were not saved: {exc}")
            return
        ctk.set_appearance_mode(self.app.settings.theme)
        self.settings_status.configure(text="Settings saved for future sessions.")

    def _refresh_alerts(self) -> None:
        try:
            rows = AlertRepository(self.app.db).list_alerts(
                severity=self.alert_severity_filter.get(),
                status=self.alert_status_filter.get(),
                source=self.alert_source_filter.get(),
                destination=self.alert_destination_filter.get(),
                start_date=self.alert_start_date_filter.get().strip(),
                end_date=self.alert_end_date_filter.get().strip(),
            )
        except (sqlite3.Error, ValueError) as exc:
            self.app.logger.exception("Could not retrieve detection alerts")
            self.alert_status_message.configure(text=f"Alerts unavailable: {exc}")
            return
        self._alert_rows = {int(row["id"]): row for row in rows}
        for item in self.alert_table.get_children():
            self.alert_table.delete(item)
        for alert in rows:
            self.alert_table.insert(
                "", "end",
                iid=str(alert["id"]),
                values=(
                    alert["timestamp"],
                    alert["severity"],
                    alert["rule_id"],
                    alert["source_address"],
                    alert["destination_address"],
                    alert["status"],
                ),
            )
        self.alert_status_message.configure(
            text=f"Showing {len(rows)} persisted alert(s)."
            if rows else "No persisted alerts match these filters."
        )
        self.alert_details.delete("1.0", "end")

    def _show_alert_details(self, _event: object = None) -> None:
        selected = self.alert_table.selection()
        if not selected:
            return
        try:
            alert_id = int(selected[0])
            alert = self._alert_rows[alert_id]
            references = json.loads(alert["supporting_packets"] or "[]")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self.app.logger.exception("Could not display selected alert")
            self.alert_details.delete("1.0", "end")
            self.alert_details.insert("end", f"Alert details are unavailable: {exc}")
            return
        if not isinstance(references, list):
            references = []
        self.alert_details.delete("1.0", "end")
        self.alert_details.insert(
            "end",
            f"Rule: {alert['rule_id']}\n"
            f"Severity: {alert['severity']}\n"
            f"Status: {alert['status']}\n"
            f"Time: {alert['timestamp']}\n"
            f"Source: {alert['source_address']}\n"
            f"Destination: {alert['destination_address']}\n"
            f"Confidence: {alert['confidence']}\n\n"
            f"{alert['description']}\n\n"
            f"Supporting packet record IDs: {', '.join(map(str, references)) or 'Unavailable'}\n"
            f"Analyst notes: {alert['analyst_notes'] or 'None'}"
        )

    def _selected_alert_row(self) -> sqlite3.Row | None:
        selected = self.alert_table.selection()
        if not selected:
            self.alert_status_message.configure(text="Select an alert first.")
            return None
        try:
            return self._alert_rows[int(selected[0])]
        except (KeyError, ValueError):
            self.alert_status_message.configure(text="The selected alert is no longer available.")
            return None

    def _set_selected_alert_status(self, status: str) -> None:
        alert = self._selected_alert_row()
        if alert is None:
            return
        try:
            updated = AlertRepository(self.app.db).update_status(alert["id"], status)
        except (sqlite3.Error, ValueError) as exc:
            self.app.logger.exception("Could not update alert status")
            messagebox.showerror("Detection alerts", f"Could not update alert: {exc}")
            return
        if not updated:
            self.alert_status_message.configure(text="The selected alert no longer exists.")
            return
        self._refresh_alerts()
        self.alert_status_message.configure(text=f"Alert marked {status}.")

    def _analyze_current_session(self) -> None:
        session_id = self._current_session_id
        if session_id is None:
            messagebox.showinfo(
                "Detection alerts",
                "Import a capture or start a live capture before analyzing a session.",
            )
            return
        if self._alert_analysis_active:
            return
        self._alert_analysis_active = True
        self.analyze_alerts_button.configure(state="disabled")
        self.alert_status_message.configure(text="Analyzing persisted packets…")
        self._start_background_worker(
            target=lambda: self._analyze_session_worker(session_id),
            name="shaheen-alert-analysis",
        )

    def _analyze_session_worker(self, session_id: int) -> None:
        connection = None
        try:
            connection = initialize_database(self.app.settings.database_path)
            repository = PacketRepository(connection)
            packets = (
                packet_record_from_row(row)
                for row in repository.iter_packet_rows(session_id)
            )
            generated = DetectionEngine().generate_alerts(packets)
            inserted = AlertRepository(connection).persist_generated(session_id, generated)
            self._alert_events.put(("complete", len(inserted)))
        except Exception as exc:
            self.app.logger.exception("Detection analysis failed for session %s", session_id)
            self._alert_events.put(("error", str(exc)))
        finally:
            if connection is not None:
                connection.close()

    def _poll_alert_events(self) -> None:
        if self._closing:
            return
        while True:
            try:
                event, payload = self._alert_events.get_nowait()
            except queue.Empty:
                break
            self._alert_analysis_active = False
            self.analyze_alerts_button.configure(state="normal")
            if event == "complete":
                        self._refresh_alerts()
                        self.alert_status_message.configure(
                            text=f"Analysis complete; {payload} new alert(s) persisted."
                        )
            else:
                self.alert_status_message.configure(
                    text=f"Analysis failed: {payload}"
                )
        self.after(200, self._poll_alert_events)

    def _poll_capture_stop_events(self) -> None:
        if self._closing:
            return
        while True:
            try:
                event, payload = self._capture_stop_events.get_nowait()
            except queue.Empty:
                break
            self._capture_stop_result_received = True
            if event == "error":
                self._capture_stop_failed = True
                self.packet_label.configure(text=f"Capture stop failed: {payload}")
            else:
                self.packet_label.configure(text="Capture stopped.")
        if self._capture_stop_pending and self._capture_stop_result_received:
            if self.capture_manager.is_running:
                self.packet_label.configure(
                    text="Capture worker is still stopping; the session remains open."
                )
            else:
                if self.capture_manager.capture_thread is not None:
                    try:
                        self.capture_manager.stop_capture(timeout=0)
                    except Exception as exc:
                        self._capture_stop_failed = True
                        self.app.logger.exception("Final capture-worker cleanup failed")
                        self.packet_label.configure(
                            text=f"Capture cleanup failed: {exc}"
                        )
                self._complete_live_capture_stop()
        self.after(200, self._poll_capture_stop_events)

    def _complete_live_capture_stop(self) -> None:
        status = (
            "failed"
            if self._capture_stop_failed
            or self.capture_manager.last_error
            or self.capture_manager.last_recording_error
            or self.capture_manager.is_running
            else "completed"
        )
        self._finish_live_session(status)
        self._capture_stop_pending = False
        self._capture_stop_result_received = False
        self._live_capture_active = False
        self._current_page = 0
        self._update_capture_controls()
        self._current_filter = self.filter_entry.get().strip()
        if self._current_session_id is not None:
            try:
                compile_filter_sql(self._current_filter)
                self._load_session_page()
            except FilterError as exc:
                self.packet_label.configure(text=f"Invalid display filter: {exc}")
        self._update_status_bar("stopped")

    def _open_alert_evidence(self) -> None:
        alert = self._selected_alert_row()
        if alert is None:
            return
        try:
            references = json.loads(alert["supporting_packets"] or "[]")
        except (TypeError, json.JSONDecodeError) as exc:
            self.app.logger.exception("Alert evidence references could not be parsed")
            messagebox.showerror("Detection alerts", f"Evidence reference is invalid: {exc}")
            return
        if not isinstance(references, list) or not references:
            messagebox.showinfo(
                "Detection alerts",
                "This alert has no linked packet records available.",
            )
            return
        try:
            row = PacketRepository(self.app.db).get_packet(int(references[0]))
        except (sqlite3.Error, TypeError, ValueError) as exc:
            self.app.logger.exception("Could not retrieve alert evidence packet")
            messagebox.showerror("Detection alerts", f"Could not load evidence: {exc}")
            return
        if row is None:
            messagebox.showinfo(
                "Detection alerts",
                "The referenced packet is no longer available in the database.",
            )
            return
        packet = packet_record_from_row(row)
        self._current_session_id = packet.session_id
        self._current_filter = ""
        self._current_page = 0
        self.filter_entry.delete(0, "end")
        self.filter_entry.insert(0, "")
        try:
            position = self.app.db.execute(
                """SELECT COUNT(*) FROM packets
                   WHERE capture_session_id = ?
                     AND (timestamp < ? OR (timestamp = ? AND id < ?))""",
                (packet.session_id, packet.timestamp, packet.timestamp, packet.record_id),
            ).fetchone()[0]
            self._current_page = int(position) // self._page_size
            self._select_navigation("Packet Analyzer")
            self._load_session_page()
            self._show_packet_details(packet)
        except (sqlite3.Error, ValueError) as exc:
            self.app.logger.exception("Could not open alert evidence packet")
            messagebox.showerror("Detection alerts", f"Could not open evidence: {exc}")

    def _select_interface(self, label: str) -> None:
        if label == "Select interface":
            self.packet_label.configure(text="Choose a discovered adapter; it will not be switched automatically.")
            self._update_capture_controls()
            return
        interface = self._interface_by_label.get(label)
        if interface is not None:
            self.packet_label.configure(
                text=f"Selected {interface.name}; capture availability is checked when capture starts."
            )
        self._update_capture_controls()

    def _refresh_interfaces(self) -> None:
        selected_label = self.interface_menu.get()
        try:
            interfaces = self.capture_manager.get_interfaces()
        except InterfaceDiscoveryError as exc:
            self._interface_by_label.clear()
            self.interface_menu.configure(values=["Select interface"])
            self.interface_menu.set("Select interface")
            self.packet_label.configure(text=f"Interface discovery failed: {exc}")
            self.app.logger.error("Interface discovery failed: %s", exc)
            self._update_capture_controls()
            return

        self._interface_by_label = {interface.label: interface for interface in interfaces}
        labels = ["Select interface", *self._interface_by_label]
        self.interface_menu.configure(values=labels)
        if selected_label in self._interface_by_label:
            self.interface_menu.set(selected_label)
        else:
            self.interface_menu.set("Select interface")
        if not interfaces:
            self.packet_label.configure(text="No network adapters were discovered.")
        else:
            self.packet_label.configure(
                text=f"Discovered {len(interfaces)} adapter(s); select one explicitly. "
                "Discovery does not confirm capture availability."
            )
        self._update_capture_controls()

    def _update_capture_controls(self) -> None:
        importing = self._import_cancel_event is not None
        capturing = self._live_capture_active
        recording = self.capture_manager.stats.recording

        def set_button(button, enabled: bool, color: str, hover: str) -> None:
            button.configure(
                state="normal" if enabled else "disabled",
                fg_color=color if enabled else "#253244",
                hover_color=hover if enabled else "#253244",
                text_color=PALETTE["text_primary"] if enabled else "#64748B",
            )

        self.interface_menu.configure(state="disabled" if capturing else "normal")
        set_button(
            self.refresh_interfaces_button,
            not capturing,
            "#334155",
            "#475569",
        )
        set_button(
            self.start_capture_button,
            not capturing and not importing and self._selected_interface() is not None,
            "#15803D",
            "#166534",
        )
        set_button(self.stop_capture_button, capturing, "#7F1D1D", "#991B1B")
        set_button(self.import_button, not capturing and not importing, "#0369A1", "#075985")
        set_button(self.cancel_import_button, importing, "#334155", "#475569")
        set_button(
            self.start_recording_button,
            capturing and not recording,
            "#0369A1",
            "#075985",
        )
        set_button(self.stop_recording_button, recording, "#334155", "#475569")
        set_button(self.pause_display_button, capturing, "#334155", "#475569")

    def _initialize_workspace_sashes(self) -> None:
        height = self.workspace.winfo_height()
        if height <= 1:
            self.after(100, self._initialize_workspace_sashes)
            return
        self.workspace.sashpos(0, int(height * 0.45))
        self.workspace.sashpos(1, int(height * 0.75))

    def _selected_interface(self) -> CaptureInterface | None:
        return self._interface_by_label.get(self.interface_menu.get())

    def _import_file(self) -> None:
        if self._live_capture_active:
            self.packet_label.configure(text="Stop live capture before opening a separate offline session.")
            return
        if self._import_cancel_event is not None:
            return
        if self._page_load_active:
            self.packet_label.configure(text="Wait for the current display filter to finish.")
            return
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng *.cap"), ("All files", "*.*")])
        if not path:
            return
        self.packet_records = []
        self.displayed_packets = []
        self.selected_packet = None
        if self._details_packet is not None:
            self._details_packet.raw_bytes = b""
            self._details_packet = None
        self._current_session_id = None
        self._offline_source_path = None
        self._current_filter = ""
        self._current_page = 0
        self._matching_packet_count = 0
        self._render_packet_table([])
        self.packet_details.delete("1.0", "end")
        self.packet_details.insert("end", "Import in progress. Packet fields will appear when rows load.")
        self.packet_hex.delete("1.0", "end")
        self.packet_hex.insert("end", "Select an imported packet to inspect its captured bytes.")
        cancel_event = threading.Event()
        self._import_cancel_event = cancel_event
        self._update_table_empty_state()
        self.import_button.configure(state="disabled")
        self.cancel_import_button.configure(state="normal")
        self._update_capture_controls()
        self.packet_label.configure(text=f"Importing {Path(path).name}...")
        self._update_status_bar("importing")

        def progress(progress_value: ImportProgress) -> None:
            try:
                self._import_events.put_nowait(("progress", progress_value))
            except queue.Full:
                pass

        def import_worker() -> None:
            connection = None
            repository = None
            session_id = None
            pending_packets = []
            try:
                connection = initialize_database(self.app.settings.database_path)
                repository = PacketRepository(connection)
                session_id = repository.create_session(
                    source_type="pcap",
                    source_path=path,
                    status="importing",
                )

                def persist_packet(packet) -> None:
                    packet.session_id = session_id
                    pending_packets.append(packet)
                    if len(pending_packets) >= 250:
                        repository.store_packets(
                            session_id,
                            pending_packets,
                            source_path=path,
                        )
                        pending_packets.clear()

                result = import_capture(
                    path,
                    persist_packet,
                    cancel_event=cancel_event,
                    on_progress=progress,
                    include_raw_bytes=False,
                )
                if pending_packets:
                    repository.store_packets(
                        session_id,
                        pending_packets,
                        source_path=path,
                    )
                repository.finish_session(
                    session_id,
                    "cancelled" if result.cancelled else "completed",
                    capture_stats={
                        "malformed_packets": result.malformed_packets,
                        "warnings": result.warnings,
                        "cancelled": result.cancelled,
                    },
                )
                self._publish_import_event(("complete", (path, result, session_id)))
            except Exception as exc:
                if repository is not None and session_id is not None:
                    if pending_packets:
                        try:
                            repository.store_packets(
                                session_id,
                                pending_packets,
                                source_path=path,
                            )
                            pending_packets.clear()
                        except Exception:
                            self.app.logger.exception(
                                "Could not flush final packet batch for failed import session %s",
                                session_id,
                            )
                    try:
                        repository.finish_session(session_id, "failed")
                    except Exception:
                        self.app.logger.exception(
                            "Could not mark failed import session %s", session_id
                        )
                self._publish_import_event(("error", (path, exc, session_id)))
            finally:
                if connection is not None:
                    connection.close()

        self._import_thread = self._start_background_worker(
            target=import_worker,
            name="shaheen-offline-import",
        )

    def _start_background_worker(
        self,
        *,
        target: Callable[[], None],
        name: str,
    ) -> threading.Thread:
        def run() -> None:
            try:
                target()
            finally:
                with self._workers_lock:
                    self._background_workers.discard(threading.current_thread())

        worker = threading.Thread(target=run, name=name, daemon=True)
        with self._workers_lock:
            self._background_workers.add(worker)
        worker.start()
        return worker

    def _publish_import_event(self, event: tuple[str, object]) -> None:
        while not self._closing:
            try:
                self._import_events.put(event, timeout=0.1)
                return
            except queue.Full:
                continue

    def _cancel_import(self) -> None:
        if self._import_cancel_event is not None:
            self._import_cancel_event.set()
            self.packet_label.configure(text="Cancelling capture import...")
            self._update_status_bar("import cancelling")

    def _clear_filter(self) -> None:
        self.filter_entry.delete(0, "end")
        self._current_filter = ""
        self._current_page = 0
        self._matching_packet_count = len(self.packet_records)
        if self._current_session_id is not None and not self._live_capture_active:
            self._load_session_page()
        else:
            self._render_packet_table()
            self.packet_label.configure(text="Display filter cleared.")
        self._update_table_empty_state()

    def _apply_filter(self) -> None:
        expr = self.filter_entry.get().strip()
        if self._import_cancel_event is not None:
            self.packet_label.configure(text="Wait for or cancel the offline import before filtering.")
            return
        if self._page_load_active:
            return
        try:
            compile_filter_sql(expr)
        except FilterError as exc:
            self.packet_label.configure(text=f"Invalid display filter: {exc}")
            self.app.logger.info("Rejected invalid display filter: %s", exc)
            return
        self._current_filter = expr
        if self._current_session_id is not None and not self._live_capture_active:
            self._current_page = 0
            self._load_session_page()
            return
        if not self.packet_records:
            self._update_table_empty_state()
            self.packet_label.configure(
                text=(
                    "Display filter is valid; waiting for packets."
                    if self._live_capture_active
                    else "Load a capture or start live capture before filtering."
                )
            )
            return
        try:
            filtered = [
                packet
                for packet in self.packet_records
                if not expr or evaluate_filter(packet, expr)
            ]
        except FilterError as exc:
            self.packet_label.configure(text=f"Invalid display filter: {exc}")
            return
        rendered_count = min(len(filtered), self.MAX_PACKET_ROWS)
        row_limit_note = (
            f"; displaying first {rendered_count:,} rows"
            if len(filtered) > self.MAX_PACKET_ROWS
            else ""
        )
        self.packet_label.configure(
            text=f"{len(filtered)} of {len(self.packet_records)} packets match{row_limit_note}"
        )
        self._render_packet_table(filtered)

    def _change_page_size(self, value: str) -> None:
        if self._page_load_active:
            self.page_size_menu.set(str(self._page_size))
            return
        try:
            page_size = int(value)
        except ValueError:
            self.packet_label.configure(text=f"Invalid page size: {value}")
            self.page_size_menu.set(str(self._page_size))
            return
        if page_size not in {100, 200, 500, 1000}:
            self.packet_label.configure(text=f"Unsupported page size: {page_size}")
            self.page_size_menu.set(str(self._page_size))
            return
        self._page_size = page_size
        self._current_page = 0
        if self._current_session_id is not None and not self._live_capture_active:
            self._load_session_page()
        else:
            self._render_packet_table()

    def _previous_packet_page(self) -> None:
        if self._page_load_active or self._current_page <= 0:
            return
        self._current_page -= 1
        self._load_session_page()

    def _next_packet_page(self) -> None:
        page_count = (self._matching_packet_count + self._page_size - 1) // self._page_size
        if self._page_load_active or self._current_page + 1 >= page_count:
            return
        self._current_page += 1
        self._load_session_page()

    def _update_page_controls(self) -> None:
        page_count = (self._matching_packet_count + self._page_size - 1) // self._page_size
        if page_count:
            self.page_label.configure(
                text=f"Page {self._current_page + 1} / {page_count} "
                f"({self._matching_packet_count:,} packets)"
            )
        else:
            self.page_label.configure(text="Page 0 / 0 (0 packets)")
        enabled = (
            self._current_session_id is not None
            and not self._live_capture_active
            and not self._page_load_active
        )
        self.previous_page_button.configure(
            state="normal" if enabled and self._current_page > 0 else "disabled"
        )
        self.next_page_button.configure(
            state=(
                "normal"
                if enabled and self._current_page + 1 < page_count
                else "disabled"
            )
        )

    def _load_session_page(self) -> None:
        session_id = self._current_session_id
        if session_id is None:
            return
        self._page_load_active = True
        page_number = self._current_page
        page_size = self._page_size
        expression = self._current_filter
        offset = page_number * page_size
        self._update_page_controls()
        self.page_size_menu.configure(state="disabled")
        self.apply_filter_button.configure(state="disabled")
        self.packet_label.configure(text="Loading packet page...")

        def page_worker() -> None:
            connection = None
            try:
                connection = initialize_database(self.app.settings.database_path)
                repository = PacketRepository(connection)
                matching_count = repository.count_packets(session_id, expression)
                rows = repository.get_packet_page(
                    session_id,
                    limit=page_size,
                    offset=offset,
                    expression=expression,
                )
                records = [packet_record_from_row(row) for row in rows]
                event = (
                    "page_complete",
                    (session_id, page_number, expression, matching_count, records),
                )
            except Exception as exc:
                event = ("page_error", exc)
            finally:
                if connection is not None:
                    connection.close()
            self._publish_import_event(event)

        self._start_background_worker(
            target=page_worker,
            name="shaheen-packet-page",
        )

    @staticmethod
    def _packet_table_values(packet: PacketRecord) -> tuple[str, ...]:
        def endpoint(address: str, port: int | None) -> str:
            if port is None or not address:
                return address or "-"
            if ":" in address:
                return f"[{address}]:{port}"
            return f"{address}:{port}"

        return (
            str(packet.packet_number),
            packet.timestamp.replace("T", " "),
            endpoint(packet.source_address, packet.source_port),
            endpoint(packet.destination_address, packet.destination_port),
            str(packet.protocol),
            f"{packet.packet_length:,}",
            packet.summary or "packet",
        )

    @staticmethod
    def _packet_table_iid(packet: PacketRecord, index: int) -> str:
        if packet.record_id is not None:
            return f"record-{packet.record_id}"
        return f"packet-{packet.packet_number}-{index}"

    def _update_table_empty_state(self) -> None:
        if self.displayed_packets:
            self.packet_empty_label.place_forget()
            return
        if self._import_cancel_event is not None:
            message = "Import in progress. Persisted packet rows will appear when the first page loads."
        elif self._live_capture_active:
            if self.packet_records and self._current_filter:
                message = "No packets match this display filter. Clear the filter to show all packets."
            else:
                message = "Waiting for packets. Capture is active; no synthetic packets are shown."
        elif self._current_session_id is None:
            message = "No capture loaded. Import a PCAP/PCAPNG or start a live capture."
        elif self._current_filter:
            message = "No packets match this display filter. Clear the filter to show all packets."
        elif self._matching_packet_count == 0:
            message = "This capture session contains no packets."
        else:
            message = "No packets are available on this page."
        self.packet_empty_label.configure(text=message)
        self.packet_empty_label.place(relx=0.5, rely=0.55, anchor="center")

    def _render_packet_table(
        self,
        packets: list[PacketRecord] | None = None,
        *,
        preserve_selection: bool = False,
    ) -> None:
        previous_selection_id = (
            self._packet_identity(self.selected_packet)
            if preserve_selection and self.selected_packet is not None
            else None
        )
        records = packets if packets is not None else self.packet_records
        row_limit = (
            self._page_size
            if self._current_session_id is not None and not self._live_capture_active
            else self.MAX_PACKET_ROWS
        )
        self.displayed_packets = list(records[:row_limit])
        children = self.packet_table.get_children("")
        if children:
            self.packet_table.delete(*children)
        self._packet_by_iid.clear()
        for index, packet in enumerate(self.displayed_packets):
            iid = self._packet_table_iid(packet, index)
            self._packet_by_iid[iid] = packet
            self.packet_table.insert(
                "",
                "end",
                iid=iid,
                values=self._packet_table_values(packet),
                tags=("even" if index % 2 == 0 else "odd",),
            )
        self.packet_table.tag_configure("even", background=PALETTE["bg_table"])
        self.packet_table.tag_configure("odd", background=PALETTE["bg_table_alt"])
        self._update_table_empty_state()
        preserved = next(
            (
                packet
                for packet in self.displayed_packets
                if previous_selection_id is not None
                and self._packet_identity(packet) == previous_selection_id
            ),
            None,
        )
        if preserved is not None:
            self._select_packet_record(preserved)
        elif self.displayed_packets:
            self._select_packet_record(self.displayed_packets[0])
        else:
            self.selected_packet = None
            self.packet_details.delete("1.0", "end")
            self.packet_hex.delete("1.0", "end")
            self.packet_details.insert("end", "Select a packet to inspect decoded fields.")
            self.packet_hex.insert("end", "Select a packet to inspect its captured bytes.")
            if self._selection_cancel_event is not None:
                self._selection_cancel_event.set()
                self._selection_cancel_event = None
            if self._details_packet is not None:
                self._details_packet.raw_bytes = b""
                self._details_packet = None

    @staticmethod
    def _packet_identity(packet: PacketRecord) -> tuple[str, int]:
        if packet.record_id is not None:
            return ("record", packet.record_id)
        return ("packet", packet.packet_number)

    def _on_packet_table_select(self, _event=None) -> None:
        selection = self.packet_table.selection()
        if not selection:
            return
        packet = self._packet_by_iid.get(selection[0])
        if packet is not None and packet is not self.selected_packet:
            self._select_packet_record(packet)

    def _select_packet_record(self, packet: PacketRecord) -> None:
        if packet is self.selected_packet and (
            self._details_packet is packet
            or (
                self._details_packet is not None
                and packet.record_id is not None
                and self._details_packet.record_id == packet.record_id
            )
        ):
            return
        self._selection_request_id += 1
        request_id = self._selection_request_id
        if self._selection_cancel_event is not None:
            self._selection_cancel_event.set()
            self._selection_cancel_event = None
        if self._details_packet is not None:
            self._details_packet.raw_bytes = b""
            self._details_packet = None
        self.selected_packet = packet
        iid = next(
            (key for key, value in self._packet_by_iid.items() if value is packet),
            None,
        )
        if iid is not None:
            self.packet_table.selection_set(iid)
            self.packet_table.focus(iid)
            self.packet_table.see(iid)
        self.packet_details.delete("1.0", "end")
        self.packet_details.insert("end", f"Loading packet #{packet.packet_number} details...")
        self.packet_hex.delete("1.0", "end")
        self.packet_hex.insert("end", f"Loading packet #{packet.packet_number} bytes...")
        if (
            packet.record_id is None
            or self._current_session_id is None
            or self._live_capture_active
        ):
            self._show_packet_details(packet)
            return

        session_id = self._current_session_id
        source_path = self._offline_source_path
        cancel_event = threading.Event()
        self._selection_cancel_event = cancel_event
        self.packet_details.delete("1.0", "end")
        self.packet_details.insert("end", f"Loading packet #{packet.packet_number} details...")

        def selection_worker() -> None:
            connection = None
            try:
                connection = initialize_database(self.app.settings.database_path)
                row = PacketRepository(connection).get_packet(packet.record_id)
                if row is None or row["capture_session_id"] != session_id:
                    raise LookupError("Selected packet record is no longer available.")
                detailed_packet = packet_record_from_row(row)
                raw_error = None
                if source_path:
                    try:
                        raw_record = read_packet_at(
                            source_path,
                            detailed_packet.packet_number,
                            cancel_event=cancel_event,
                        )
                        if (
                            raw_record.timestamp != detailed_packet.timestamp
                            or raw_record.packet_length != detailed_packet.packet_length
                        ):
                            raw_error = (
                                "The source capture no longer matches the imported packet record."
                            )
                        else:
                            detailed_packet.raw_bytes = raw_record.raw_bytes
                    except Exception as exc:
                        raw_error = str(exc)
                else:
                    raw_error = "Raw bytes are not available for this session."
                event = ("selection_complete", (request_id, detailed_packet, raw_error))
            except Exception as exc:
                event = ("selection_error", (request_id, exc))
            finally:
                if connection is not None:
                    connection.close()
            self._publish_import_event(event)

        self._start_background_worker(
            target=selection_worker,
            name=f"shaheen-packet-detail-{packet.record_id}",
        )

    def _show_packet_details(self, packet: PacketRecord) -> None:
        self._details_packet = packet
        self.selected_packet = packet
        self.packet_details.delete("1.0", "end")
        lines = [
            f"Packet number: {packet.packet_number}",
            f"Record ID: {packet.record_id}" if packet.record_id is not None else "Record ID: pending",
            f"Timestamp: {packet.timestamp}",
            "Protocol tree:",
        ]
        for layer in packet.protocol_tree:
            lines.append(f"  {layer['name']}")
            for key, value in layer["fields"].items():
                lines.append(f"    {key}: {value}")
        self.packet_details.insert("end", "\n".join(lines))
        self.packet_hex.delete("1.0", "end")
        self.packet_hex.insert(
            "end",
            packet.hex_dump if packet.raw_bytes else "Raw bytes are not available for this packet.",
        )

    def _create_investigation(self) -> None:
        title = self.case_title_entry.get().strip()
        try:
            investigation_id = self.investigations.create_investigation(title)
        except Exception as exc:
            self.packet_label.configure(text=f"Could not create investigation: {exc}")
            self.app.logger.exception("Investigation creation failed")
            return
        self.active_investigation_id = investigation_id
        self.investigation_label.configure(text=f"Active investigation: {title} (#{investigation_id})")
        self.case_title_entry.delete(0, "end")

    def _add_selected_packet_to_case(self) -> None:
        if self.active_investigation_id is None:
            self.packet_label.configure(text="Create an investigation before adding evidence.")
            return
        if self.selected_packet is None:
            self.packet_label.configure(text="Select a packet before adding evidence.")
            return
        try:
            self.investigations.add_packet_event(
                self.active_investigation_id,
                self.selected_packet,
            )
        except Exception as exc:
            self.packet_label.configure(text=f"Could not add packet to investigation: {exc}")
            self.app.logger.exception("Adding packet to investigation failed")
            return
        self.packet_label.configure(
            text=f"Packet #{self.selected_packet.packet_number} added to investigation."
        )

    def _export_packets_csv(self) -> None:
        if not self.packet_records and self._current_session_id is None:
            self.packet_label.configure(text="There are no packets to export.")
            return
        if self._import_cancel_event is not None:
            self.packet_label.configure(text="Wait for or cancel the offline import before exporting.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Export packet metadata",
            initialdir=self.app.settings.report_path,
        )
        if not path:
            return
        try:
            if self._current_session_id is not None:
                packet_rows = PacketRepository(
                    self.app.db
                ).iter_packet_rows(self._current_session_id)
                CSVExporter.export_packets(path, packet_rows)
            else:
                CSVExporter.export_packets(path, self.packet_records)
        except Exception as exc:
            self.packet_label.configure(text=f"CSV export failed: {exc}")
            self.app.logger.exception("Packet CSV export failed")
            return
        self.packet_label.configure(text=f"Packet metadata exported to {Path(path).name}")

    def _export_investigation(self) -> None:
        if self.active_investigation_id is None:
            self.packet_label.configure(text="Create an investigation before exporting its timeline.")
            return
        investigation = self.investigations.get_investigation(self.active_investigation_id)
        if investigation is None:
            self.packet_label.configure(text="The active investigation no longer exists.")
            return
        events = self.investigations.get_timeline(self.active_investigation_id)
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF report", "*.pdf"), ("CSV timeline", "*.csv")],
            title="Export investigation timeline",
            initialdir=self.app.settings.report_path,
        )
        if not path:
            return
        try:
            if Path(path).suffix.lower() == ".csv":
                CSVExporter.export_timeline(path, events)
            else:
                PDFReport(path).generate_investigation(
                    f"Shaheen Investigation #{self.active_investigation_id}",
                    investigation,
                    events,
                )
        except Exception as exc:
            self.packet_label.configure(text=f"Investigation export failed: {exc}")
            self.app.logger.exception("Investigation export failed")
            return
        self.packet_label.configure(text=f"Investigation exported to {Path(path).name}")

    def _start_live_capture(self) -> None:
        if self._page_load_active:
            self.packet_label.configure(text="Wait for the current display filter to finish.")
            return
        if self._import_cancel_event is not None:
            self.packet_label.configure(text="Wait for or cancel the offline import before live capture.")
            return
        interface = self._selected_interface()
        if interface is None:
            self.packet_label.configure(text="Select a discovered interface before starting capture.")
            return
        storage_worker = None
        session_id = None
        try:
            repository = PacketRepository(self.app.db)
            session_id = repository.create_session(
                source_type="live",
                source_path=interface.name,
                status="capturing",
            )
            storage_worker = PacketStorageWorker(
                self.app.settings.database_path,
                session_id,
            )
            self.capture_manager.session_id = session_id
            self.capture_manager.packet_sink = storage_worker.submit
            self.capture_manager.start_capture(
                interface.name,
                capture_filter=self.app.settings.capture_filter or None,
            )
            self._live_session_id = session_id
            self._current_session_id = session_id
            self._offline_source_path = None
            self._current_filter = self.filter_entry.get().strip()
            self._current_page = 0
            self._matching_packet_count = 0
            self._packet_storage_worker = storage_worker
            self._packets_persisted = 0
            self._metadata_packets_dropped = 0
            self.packet_records.clear()
            self.displayed_packets.clear()
            self.selected_packet = None
            if self._details_packet is not None:
                self._details_packet.raw_bytes = b""
                self._details_packet = None
            self._live_capture_active = True
            self._display_paused = False
            self._display_paused_packets = 0
            self._update_capture_controls()
            self._render_packet_table([])
            self.packet_label.configure(
                text=f"Capture started on {interface.name}; waiting for packets. "
                "Capture filters are unset; display filtering is separate."
            )
            self._update_status_bar(f"running on {interface.name}")
        except Exception as exc:
            self.capture_manager.packet_sink = None
            if storage_worker is not None:
                try:
                    storage_worker.stop()
                except Exception:
                    self.app.logger.exception(
                        "Packet storage worker shutdown after capture start failure"
                    )
            if session_id is not None:
                try:
                    PacketRepository(self.app.db).finish_session(session_id, "failed")
                except Exception:
                    self.app.logger.exception("Could not finalize failed live session")
            self.packet_label.configure(text=f"Capture failed: {exc}")
            self.app.logger.error("Capture failed on %s: %s", interface.name, exc)
            self._update_capture_controls()
            self._update_status_bar("start failed")

    def _stop_live_capture(self) -> None:
        stop_failed = False
        try:
            self.capture_manager.stop_capture()
        except Exception as exc:
            stop_failed = True
            self.packet_label.configure(text=f"Capture stop failed: {exc}")
            self.app.logger.exception("Stopping capture failed")
        finally:
            self._finish_live_session(
                "failed"
                if stop_failed
                or self.capture_manager.last_error
                or self.capture_manager.last_recording_error
                else "completed"
            )
            self._live_capture_active = False
            self._current_page = 0
            self._update_capture_controls()
            self._current_filter = self.filter_entry.get().strip()
            if self._current_session_id is not None:
                try:
                    compile_filter_sql(self._current_filter)
                    self._load_session_page()
                except FilterError as exc:
                    self.packet_label.configure(text=f"Invalid display filter: {exc}")
            self._update_status_bar("stopped")

    def _finish_live_session(self, status: str) -> None:
        worker = self._packet_storage_worker
        session_id = self._live_session_id
        self._packet_storage_worker = None
        self._live_session_id = None
        self.capture_manager.packet_sink = None
        if worker is not None:
            try:
                worker.stop()
            except Exception as exc:
                status = "failed"
                self.app.logger.exception("Packet metadata storage shutdown failed")
                self.packet_label.configure(text=f"Packet metadata storage failed: {exc}")
            finally:
                self._packets_persisted = worker.packets_persisted
                self._metadata_packets_dropped = worker.dropped_packets
        if session_id is not None:
            try:
                stats = self.capture_manager.stats
                PacketRepository(self.app.db).finish_session(
                    session_id,
                    status,
                    capture_stats={
                        "packets_received": stats.packets_received,
                        "packets_accepted": stats.packets_accepted,
                        "packets_persisted": self._packets_persisted,
                        "packets_recorded": stats.packets_recorded,
                        "packets_delivered": stats.packets_delivered,
                        "display_queue_dropped": stats.packets_dropped_from_display_queue,
                        "metadata_queue_dropped": self._metadata_packets_dropped,
                        "malformed_packets": stats.malformed_packets,
                        "recording_path": self.capture_manager.last_recording_path,
                        "recording_error": self.capture_manager.last_recording_error,
                        "capture_error": self.capture_manager.last_error,
                    },
                )
            except Exception as exc:
                self.app.logger.exception(
                    "Could not finalize capture session %s", session_id
                )
                self.packet_label.configure(text=f"Capture session persistence failed: {exc}")

    def _toggle_display_pause(self) -> None:
        if not self._live_capture_active:
            self.packet_label.configure(text="Start live capture before pausing packet display.")
            return
        self._display_paused = not self._display_paused
        if self._display_paused:
            self.pause_display_button.configure(text="Resume display")
            self.packet_label.configure(
                text="Display paused; acquisition and any active recording continue. "
                "Packets received while paused are not retained in the display."
            )
        else:
            self.pause_display_button.configure(text="Pause display")
            self.packet_label.configure(
                text=f"Display resumed; {self._display_paused_packets} packet(s) arrived while paused "
                "and are not shown."
            )
            self._display_paused_packets = 0
        self._update_status_bar("running")
        self._update_capture_controls()

    def _start_recording(self) -> None:
        if not self._live_capture_active:
            self.packet_label.configure(text="Start capture before starting a recording.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pcapng",
            filetypes=[("PCAPNG capture", "*.pcapng"), ("PCAP capture", "*.pcap")],
            title="Record live traffic",
        )
        if not path:
            return
        overwrite = False
        if Path(path).exists():
            overwrite = messagebox.askyesno(
                "Replace capture file?",
                f"The file already exists:\n{path}\n\nReplace it?",
                parent=self,
            )
            if not overwrite:
                return
        try:
            self.capture_manager.start_recording(path, overwrite=overwrite)
        except Exception as exc:
            self.packet_label.configure(text=f"Recording could not start: {exc}")
            self.app.logger.error("Recording start failed: %s", exc)
            return
        self.packet_label.configure(text=f"Recording live packets to {Path(path).name}")
        self._update_status_bar("running")
        self._update_capture_controls()

    def _stop_recording(self) -> None:
        try:
            path = self.capture_manager.stop_recording()
        except Exception as exc:
            self.packet_label.configure(text=f"Recording finalization failed: {exc}")
            self.app.logger.exception("Recording finalization failed")
            return
        if path:
            self.packet_label.configure(
                text=f"Recording finalized: {path} "
                f"({self.capture_manager.stats.packets_recorded} packet(s) written)"
            )
        else:
            self.packet_label.configure(text="No recording is active.")
        self._update_status_bar("running" if self._live_capture_active else "idle")
        self._update_capture_controls()

    def _update_status_bar(self, state: str) -> None:
        stats = self.capture_manager.stats
        persisted = (
            self._packet_storage_worker.packets_persisted
            if self._packet_storage_worker is not None
            else self._packets_persisted
        )
        metadata_dropped = (
            self._packet_storage_worker.dropped_packets
            if self._packet_storage_worker is not None
            else self._metadata_packets_dropped
        )
        display_status = "paused" if self._display_paused else "active"
        self.status_bar.configure(text=f"Capture: {state}   |   Received: {stats.packets_received}   |   Accepted: {stats.packets_accepted}   |   Persisted: {persisted}   |   Recorded: {stats.packets_recorded}   |   Delivered: {stats.packets_delivered}   |   Malformed: {stats.malformed_packets}   |   Queue Drops: {stats.packets_dropped_from_display_queue + metadata_dropped}   |   Display: {display_status}")
        if state.lower() in ("capturing", "running"):
            self.header_state.configure(text="Capture Capturing", text_color=PALETTE["text_success"])
            if hasattr(self, 'live_status_badge'):
                self.live_status_badge.configure(text="CAPTURING", text_color=PALETTE["text_success"])
        elif state.lower() in ("paused",):
            self.header_state.configure(text="Capture Paused", text_color=PALETTE["warning"])
            if hasattr(self, 'live_status_badge'):
                self.live_status_badge.configure(text="PAUSED", text_color=PALETTE["warning"])
        elif state.lower() in ("error", "failed"):
            self.header_state.configure(text="Capture Error", text_color=PALETTE["text_danger"])
            if hasattr(self, 'live_status_badge'):
                self.live_status_badge.configure(text="ERROR", text_color=PALETTE["text_danger"])
        elif state.lower() in ("stopped", "idle", "complete"):
            self.header_state.configure(text="Capture Idle", text_color=PALETTE["text_label"])
            if hasattr(self, 'live_status_badge'):
                self.live_status_badge.configure(text="IDLE", text_color=PALETTE["text_label"])
        else:
            self.header_state.configure(text=f"Capture {state}", text_color=PALETTE["text_label"])
            if hasattr(self, 'live_status_badge'):
                self.live_status_badge.configure(text=state.upper(), text_color=PALETTE["text_label"])
        self.status_detail_bar.configure(
            text=(
                f"Received: {stats.packets_received}  |  Accepted: {stats.packets_accepted}  |  "
                f"Persisted: {persisted}  |  Recorded: {stats.packets_recorded}  |  "
                f"Delivered: {stats.packets_delivered}\n"
                f"Malformed: {stats.malformed_packets}  |  "
                f"Display queue drops: {stats.packets_dropped_from_display_queue}  |  "
                f"Metadata queue drops: {metadata_dropped}  |  Display: {display_status}"
            )
        )

    def _poll_capture_queue(self) -> None:
        live_packets = []
        for _ in range(500):
            try:
                event_type, payload = self._import_events.get_nowait()
            except queue.Empty:
                break
            if event_type == "progress":
                progress = payload
                if progress.total_bytes:
                    percent = min(100, int(progress.bytes_read * 100 / progress.total_bytes))
                    self.packet_label.configure(
                        text=f"Importing: {progress.packets_read} packets ({percent}%)"
                    )
                    self._update_status_bar("importing")
            elif event_type == "complete":
                path, result, session_id = payload
                self._current_session_id = session_id
                self._offline_source_path = path
                self._current_filter = ""
                self._current_page = 0
                self._matching_packet_count = result.packets_read
                self._load_session_page()
                state = "cancelled" if result.cancelled else "complete"
                warning_text = (
                    f"; {result.malformed_packets} malformed packet(s) skipped"
                    if result.malformed_packets
                    else ""
                )
                self.packet_label.configure(
                    text=f"Import {state}: {result.packets_read} packets from "
                    f"{Path(path).name} (session #{session_id}){warning_text}"
                    + (
                        f"; page size {self._page_size:,}"
                        if result.packets_read > self._page_size
                        else ""
                    )
                )
                self.app.logger.info(
                    "Imported %s packets from %s (cancelled=%s, malformed=%s)",
                    result.packets_read,
                    path,
                    result.cancelled,
                    result.malformed_packets,
                )
                for warning in result.warnings:
                    self.app.logger.warning("%s", warning)
                self._import_cancel_event = None
                self.import_button.configure(state="normal")
                self.cancel_import_button.configure(state="disabled")
                self._update_capture_controls()
                self._update_status_bar("import cancelled" if result.cancelled else "idle")
            elif event_type == "page_complete":
                session_id, page_number, expression, matching_count, records = payload
                self._page_load_active = False
                if (
                    session_id != self._current_session_id
                    or page_number != self._current_page
                    or expression != self._current_filter
                ):
                    self._update_page_controls()
                    continue
                self._matching_packet_count = matching_count
                self.packet_records = records
                self._render_packet_table(records)
                self._update_page_controls()
                self.page_size_menu.configure(state="normal")
                self.apply_filter_button.configure(state="normal")
                if matching_count == 0 and self._current_filter:
                    self.packet_label.configure(
                        text="No packets match this display filter. Clear the filter to show all packets."
                    )
                elif matching_count == 0:
                    self.packet_label.configure(text="This capture session contains no packets.")
                else:
                    self.packet_label.configure(
                        text=f"Showing {len(records):,} of {matching_count:,} matching "
                        f"packet(s) on page {page_number + 1}."
                    )
            elif event_type == "page_error":
                self._page_load_active = False
                self._update_page_controls()
                self.page_size_menu.configure(state="normal")
                self.apply_filter_button.configure(state="normal")
                self.packet_label.configure(text=f"Could not load packet page: {payload}")
                self.app.logger.error("Loading database-backed packet page failed: %s", payload)
            elif event_type == "selection_complete":
                request_id, packet, raw_error = payload
                if request_id != self._selection_request_id:
                    packet.raw_bytes = b""
                    continue
                self._show_packet_details(packet)
                if raw_error:
                    self.packet_details.insert(
                        "end",
                        f"\n\nRaw packet bytes unavailable: {raw_error}",
                    )
                    self.app.logger.warning(
                        "Raw bytes for packet %s are unavailable: %s",
                        packet.packet_number,
                        raw_error,
                    )
            elif event_type == "selection_error":
                request_id, exc = payload
                if request_id == self._selection_request_id:
                    self.packet_details.delete("1.0", "end")
                    self.packet_details.insert("end", f"Could not load selected packet: {exc}")
                    self.packet_hex.delete("1.0", "end")
                    self.packet_hex.insert("end", f"Could not load packet bytes: {exc}")
                    self.app.logger.error("Packet detail lookup failed: %s", exc)
            elif event_type == "error":
                path, exc, session_id = payload
                if session_id is not None:
                    self._current_session_id = session_id
                    self._offline_source_path = path
                    self._current_filter = ""
                    self._current_page = 0
                    self._load_session_page()
                self.packet_label.configure(
                    text=f"Capture import failed for session #{session_id}: {exc}"
                )
                self.app.logger.error("PCAP import failed for %s: %s", path, exc)
                self._import_cancel_event = None
                self.import_button.configure(state="normal")
                self.cancel_import_button.configure(state="disabled")
                self._update_capture_controls()
                self._update_table_empty_state()
                self._update_status_bar("import failed")

        item = self.capture_manager.consumer()
        for _ in range(999):
            if item is None:
                break
            kind, payload = item
            if kind == "error":
                self.packet_label.configure(text=f"Capture error: {payload}")
                self._live_capture_active = False
                self._finish_live_session("failed")
                self._update_capture_controls()
                self._update_status_bar("capture error")
                self.app.logger.error("Capture backend error: %s", payload)
            elif kind == "recording_error":
                self.packet_label.configure(text=f"Recording error: {payload}")
                self.app.logger.error("Capture recording error: %s", payload)
            elif kind == "storage_error":
                self.packet_label.configure(text=f"Packet metadata storage warning: {payload}")
                self.app.logger.error("Packet metadata storage warning: %s", payload)
            elif kind == "packet_error":
                self.app.logger.warning("Packet %s could not be decoded: %s", *payload)
            elif kind == "packet":
                if self._display_paused:
                    self._display_paused_packets += 1
                else:
                    live_packets.append(payload)
            item = self.capture_manager.consumer()

        if live_packets and not self._display_paused:
            self.packet_records.extend(live_packets)
            if self._live_capture_active and len(self.packet_records) > self.MAX_PACKET_ROWS:
                excess = len(self.packet_records) - self.MAX_PACKET_ROWS
                del self.packet_records[:excess]
            expr = self.filter_entry.get().strip()
            try:
                matching_packets = [
                    packet
                    for packet in self.packet_records
                    if not expr or evaluate_filter(packet, expr)
                ]
            except FilterError as exc:
                matching_packets = []
                self.packet_label.configure(text=f"Invalid display filter: {exc}")
            self._render_packet_table(
                matching_packets,
                preserve_selection=True,
            )
            self.packet_label.configure(
                text=f"Live buffer retains the latest {len(self.packet_records)} received packet(s); "
                f"{len(matching_packets)} match the current display filter. "
                "Recording is independent of display filtering."
            )
        if self._live_capture_active:
            self._update_status_bar("running")
        self.after(200, self._poll_capture_queue)

    def _on_close(self) -> None:
        self._closing = True
        capture_stop_failed = False
        if self._import_cancel_event is not None:
            self._import_cancel_event.set()
        if self._selection_cancel_event is not None:
            self._selection_cancel_event.set()
        try:
            self.capture_manager.stop_capture()
        except Exception as exc:
            capture_stop_failed = True
            self.app.logger.exception("Capture shutdown failed")
            messagebox.showerror(
                "Capture shutdown issue",
                f"Capture resources did not shut down cleanly:\n{exc}",
                parent=self,
            )
        finally:
            deadline = time.monotonic() + 5.0
            with self._workers_lock:
                workers = list(self._background_workers)
            for worker in workers:
                worker.join(timeout=max(0.0, deadline - time.monotonic()))
            still_running = [worker.name for worker in workers if worker.is_alive()]
            if still_running:
                capture_stop_failed = True
                self.app.logger.error(
                    "Background workers exceeded shutdown timeout: %s",
                    ", ".join(still_running),
                )
                messagebox.showwarning(
                    "Background work still stopping",
                    "The application is closing, but these workers did not stop "
                    f"within five seconds: {', '.join(still_running)}",
                    parent=self,
                )
            self._finish_live_session(
                "failed"
                if self.capture_manager.last_error
                or self.capture_manager.last_recording_error
                else "completed"
            )
            self.app.db.close()
            self.destroy()


def launch(app: ShaheenApplication | None = None) -> None:
    app = app or ShaheenApplication(load_settings())
    app.bootstrap()
    window = ShaheenMainWindow(app)
    window.mainloop()
