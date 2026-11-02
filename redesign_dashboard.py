with open(r'D:\Shaneen\gui\main_window.py') as f:
    content = f.read()

# Add imports
if 'from tkinter import ttk' in content and 'Image' not in content:
    content = content.replace('from tkinter import filedialog, messagebox, ttk\n',
                              'from tkinter import filedialog, messagebox, ttk\nimport io\nimport base64\ntry:\n    from PIL import Image\nexcept Exception:\n    Image = None\n')

# Redesign dashboard
old = '''    def _build_navigation_workspaces(self) -> None:
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
        dashboard.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            dashboard,
            text="Network Monitoring Overview",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=PALETTE["text_primary"],
            anchor="w",
        ).grid(row=0, column=0, padx=20, pady=(18, 12), sticky="ew")
        summary_card = ctk.CTkFrame(dashboard, fg_color=PALETTE["bg_card"], border_width=1, border_color=PALETTE["border"], corner_radius=10)
        summary_card.grid(row=1, column=0, padx=20, pady=(0, 12), sticky="ew")
        summary_card.grid_columnconfigure(0, weight=1)
        self.dashboard_summary = ctk.CTkLabel(
            summary_card, text="", justify="left", anchor="nw", wraplength=850,
            text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=12),
        )
        self.dashboard_summary.grid(row=0, column=0, padx=18, pady=16, sticky="ew")
        status_card = ctk.CTkFrame(dashboard, fg_color=PALETTE["bg_card"], border_width=1, border_color=PALETTE["border"], corner_radius=10)
        status_card.grid(row=2, column=0, padx=20, pady=(0, 12), sticky="ew")
        status_card.grid_columnconfigure(0, weight=1)
        self.dashboard_status = ctk.CTkLabel(
            status_card, text="", justify="left", anchor="w", wraplength=850,
            text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11),
        )
        self.dashboard_status.grid(row=0, column=0, padx=18, pady=14, sticky="ew")
        ctk.CTkButton(
            dashboard, text="Refresh overview", command=self._refresh_dashboard,
        ).grid(row=3, column=0, padx=16, pady=12, sticky="w")
        ctk.CTkLabel(
            dashboard,
            text="Shaheen stores packet metadata locally. Detection results are indicators for review, not proof of compromise.",
            justify="left",
            text_color=PALETTE["text_label"],
            wraplength=850,
        ).grid(row=4, column=0, padx=16, pady=(6, 16), sticky="ew")'''

new = '''    def _build_navigation_workspaces(self) -> None:
        self._navigation_pages: dict[str, ctk.CTkFrame] = {}
        self._alert_events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._capture_stop_events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._alert_analysis_active = False
        self._capture_stop_pending = False
        self._capture_stop_result_received = False
        self._capture_stop_failed = False
        self._alert_rows: dict[int, sqlite3.Row] = {}

        def page(name: str) -> ctk.CTkFrame:
            frame = ctk.CTkFrame(self.content, fg_color="transparent")
            frame.grid(row=3, column=0, sticky="nsew", padx=8, pady=(0, 8))
            frame.grid_remove()
            self._navigation_pages[name] = frame
            return frame

        dashboard = page("Dashboard")
        dashboard.grid_columnconfigure(0, weight=1)
        dashboard.grid_columnconfigure(1, weight=1)
        dashboard.grid_columnconfigure(2, weight=1)
        dashboard.grid_columnconfigure(3, weight=1)
        ctk.CTkLabel(
            dashboard,
            text="Network Monitoring Overview",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=PALETTE["text_primary"],
            anchor="w",
        ).grid(row=0, column=0, columnspan=4, padx=20, pady=(18, 16), sticky="ew")

        self.dashboard_cards = {}
        def make_card(col, title, key):
            card = ctk.CTkFrame(dashboard, fg_color=PALETTE["bg_card"], border_width=1, border_color=PALETTE["border"], corner_radius=12)
            card.grid(row=1, column=col, padx=10, pady=(0, 12), sticky="ew")
            card.grid_columnconfigure(0, weight=1)
            lbl = ctk.CTkLabel(card, text=title, text_color=PALETTE["text_label"], font=ctk.CTkFont(size=11))
            lbl.grid(row=0, column=0, padx=16, pady=(14, 6), sticky="w")
            val = ctk.CTkLabel(card, text="-", text_color=PALETTE["text_primary"], font=ctk.CTkFont(size=26, weight="bold"))
            val.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="w")
            self.dashboard_cards[key] = val
            return card

        make_card(0, "Total Sessions", "sessions")
        make_card(1, "Persisted Packets", "packets")
        make_card(2, "Detection Alerts", "alerts")
        make_card(3, "Capture State", "state")

        health_card = ctk.CTkFrame(dashboard, fg_color="rgba(16,185,129,0.1)", border_width=1, border_color="#10B981", corner_radius=12)
        health_card.grid(row=2, column=0, columnspan=4, padx=20, pady=(4, 12), sticky="ew")
        health_card.grid_columnconfigure(0, weight=1)
        self.dashboard_status = ctk.CTkLabel(
            health_card, text="", justify="left", anchor="w",
            text_color="#34D399", font=ctk.CTkFont(size=11),
        )
        self.dashboard_status.grid(row=0, column=0, padx=18, pady=14, sticky="ew")

        actions = ctk.CTkFrame(dashboard, fg_color="transparent")
        actions.grid(row=3, column=0, columnspan=4, padx=20, pady=8, sticky="w")
        refresh_btn = ctk.CTkButton(
            actions, text="Refresh overview", command=self._refresh_dashboard,
            fg_color=PALETTE["primary"], hover_color=PALETTE["primary_hover"],
            text_color=PALETTE["text_primary"], corner_radius=8, height=36, width=160,
        )
        refresh_btn.grid(row=0, column=0, padx=0, pady=0)
        ctk.CTkLabel(
            dashboard,
            text="Shaheen stores packet metadata locally. Detection results are indicators for review, not proof of compromise.",
            justify="left",
            text_color=PALETTE["text_label"],
            wraplength=950,
        ).grid(row=4, column=0, columnspan=4, padx=20, pady=(12, 16), sticky="ew")'''

if old not in content:
    print('not found')
else:
    content = content.replace(old, new)
    # Update refresh dashboard
    old2 = '''    def _refresh_dashboard(self) -> None:
        try:
            session_count = self.app.db.execute(
                "SELECT COUNT(*) FROM capture_sessions"
            ).fetchone()[0]
            packet_count = self.app.db.execute(
                "SELECT COUNT(*) FROM packets"
            ).fetchone()[0]
            alert_count = self.app.db.execute(
                "SELECT COUNT(*) FROM alerts"
            ).fetchone()[0]
            current_session = (
                str(self._current_session_id)
                if self._current_session_id is not None
                else "None selected"
            )
            self.dashboard_summary.configure(
                text=(
                    f"Capture Sessions: {session_count}\\n"
                    f"Persisted Packets: {packet_count}\\n"
                    f"Detection Alerts: {alert_count}\\n"
                    f"Selected Session: {current_session}\\n"
                    f"Capture State: {'Running' if self.capture_manager.is_running else 'Stopped'}"
                ),
                text_color=PALETTE["text_primary"],
            )
            available, message = self.capture_manager.capture_provider_status()
            self.dashboard_status.configure(
                text=message,
                text_color=PALETTE["text_success"] if available else PALETTE["text_danger"],
            )
        except sqlite3.Error as exc:
            self.app.logger.exception("Could not load Dashboard statistics")
            self.dashboard_summary.configure(text=f"Dashboard data unavailable: {exc}", text_color=PALETTE["text_danger"])'''
    new2 = '''    def _refresh_dashboard(self) -> None:
        try:
            session_count = self.app.db.execute(
                "SELECT COUNT(*) FROM capture_sessions"
            ).fetchone()[0]
            packet_count = self.app.db.execute(
                "SELECT COUNT(*) FROM packets"
            ).fetchone()[0]
            alert_count = self.app.db.execute(
                "SELECT COUNT(*) FROM alerts"
            ).fetchone()[0]
            if hasattr(self, "dashboard_cards"):
                self.dashboard_cards["sessions"].configure(text=f"{session_count}")
                self.dashboard_cards["packets"].configure(text=f"{packet_count:,}")
                self.dashboard_cards["alerts"].configure(text=f"{alert_count}", text_color=PALETTE["text_danger"] if alert_count > 0 else PALETTE["text_primary"])
                self.dashboard_cards["state"].configure(text="Running" if self.capture_manager.is_running else "Stopped")
            available, message = self.capture_manager.capture_provider_status()
            if hasattr(self, "dashboard_status"):
                self.dashboard_status.configure(
                    text=f"✓ {message}",
                    text_color="#34D399" if available else PALETTE["text_danger"],
                )
        except sqlite3.Error as exc:
            self.app.logger.exception("Could not load Dashboard statistics")
            if hasattr(self, "dashboard_status"):
                self.dashboard_status.configure(text=f"Dashboard data unavailable: {exc}", text_color=PALETTE["text_danger"])'''
    if old2 in content:
        content = content.replace(old2, new2)
    with open(r'D:\Shaneen\gui\main_window.py', 'w') as f:
        f.write(content)
    print('ok')
