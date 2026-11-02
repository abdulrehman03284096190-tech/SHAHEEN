from __future__ import annotations

import json
import sqlite3
from tkinter import ttk
import customtkinter as ctk

from gui.theme import PALETTE


class EnhancedDashboard:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = ctk.CTkFrame(parent, fg_color=PALETTE["bg_panel"])
        self.frame.grid_columnconfigure((0,1,2,3), weight=1)
        
        # Header
        ctk.CTkLabel(self.frame, text="SOC Dashboard", font=ctk.CTkFont(size=24, weight="bold"), 
                    text_color=PALETTE["text_primary"]).grid(row=0, column=0, columnspan=4, padx=20, pady=(20,10), sticky="w")
        
        # Stats cards
        self.stats_labels = {}
        stats = [
            ("Total Packets", "total_packets", 1, 0),
            ("Alerts", "total_alerts", 1, 1),
            ("Critical/High", "critical_high", 1, 2),
            ("Active Sessions", "sessions", 1, 3),
        ]
        for title, key, row, col in stats:
            card = ctk.CTkFrame(self.frame, fg_color=PALETTE["bg_card"], corner_radius=10)
            card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12), text_color=PALETTE["text_label"]).pack(padx=15, pady=(10,5), anchor="w")
            lbl = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=28, weight="bold"), text_color=PALETTE["text_primary"])
            lbl.pack(padx=15, pady=(0,10), anchor="w")
            self.stats_labels[key] = lbl
    
    def refresh(self):
        try:
            conn = self.app.db
            total_packets = conn.execute("SELECT COUNT(*) as c FROM packets").fetchone()["c"]
            total_alerts = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"]
            critical_high = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE severity IN ('critical','high')").fetchone()["c"]
            sessions = conn.execute("SELECT COUNT(*) as c FROM capture_sessions").fetchone()["c"]
            
            self.stats_labels["total_packets"].configure(text=str(total_packets))
            self.stats_labels["total_alerts"].configure(text=str(total_alerts))
            self.stats_labels["critical_high"].configure(text=str(critical_high))
            self.stats_labels["sessions"].configure(text=str(sessions))
        except Exception as e:
            pass
