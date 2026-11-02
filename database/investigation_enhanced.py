from __future__ import annotations

import sqlite3
from datetime import datetime


class EnhancedInvestigationManager:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self._ensure_tables()
    
    def _ensure_tables(self):
        with self.connection:
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    description TEXT,
                    severity TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'Open',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    analyst_notes TEXT
                )
            """)
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS investigation_packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER,
                    packet_id INTEGER,
                    added_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
                    FOREIGN KEY(packet_id) REFERENCES packets(id) ON DELETE CASCADE,
                    UNIQUE(investigation_id, packet_id)
                )
            """)
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS investigation_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER,
                    alert_id INTEGER,
                    added_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
                    FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
                    UNIQUE(investigation_id, alert_id)
                )
            """)
    
    def create_investigation(self, title: str, description: str = "", severity: str = "medium") -> int:
        with self.connection:
            cursor = self.connection.execute(
                "INSERT INTO investigations(title, description, severity, status) VALUES (?, ?, ?, 'Open')",
                (title, description, severity)
            )
            return cursor.lastrowid
    
    def add_packet(self, investigation_id: int, packet_id: int) -> bool:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT OR IGNORE INTO investigation_packets(investigation_id, packet_id) VALUES (?, ?)",
                    (investigation_id, packet_id)
                )
            return True
        except Exception:
            return False
    
    def add_alert(self, investigation_id: int, alert_id: int) -> bool:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT OR IGNORE INTO investigation_alerts(investigation_id, alert_id) VALUES (?, ?)",
                    (investigation_id, alert_id)
                )
            return True
        except Exception:
            return False
    
    def list_investigations(self):
        return self.connection.execute("SELECT * FROM investigations ORDER BY created_at DESC").fetchall()
