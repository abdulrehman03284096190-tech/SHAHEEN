from __future__ import annotations

import sqlite3
from typing import List


class WatchlistManager:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self._ensure_table()
    
    def _ensure_table(self):
        with self.connection:
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS ip_watchlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE,
                    reason TEXT,
                    added_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    added_by TEXT DEFAULT 'user'
                )
            """)
    
    def add_ip(self, ip_address: str, reason: str = "") -> bool:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT OR IGNORE INTO ip_watchlist(ip_address, reason) VALUES (?, ?)",
                    (ip_address.strip(), reason.strip())
                )
            return True
        except Exception:
            return False
    
    def remove_ip(self, ip_address: str) -> bool:
        try:
            with self.connection:
                self.connection.execute(
                    "DELETE FROM ip_watchlist WHERE ip_address = ?",
                    (ip_address.strip(),)
                )
            return True
        except Exception:
            return False
    
    def get_watchlist(self) -> List[str]:
        rows = self.connection.execute("SELECT ip_address FROM ip_watchlist ORDER BY added_at DESC").fetchall()
        return [row["ip_address"] for row in rows]
    
    def is_watchlisted(self, ip_address: str) -> bool:
        row = self.connection.execute("SELECT 1 FROM ip_watchlist WHERE ip_address = ?", (ip_address,)).fetchone()
        return row is not None
