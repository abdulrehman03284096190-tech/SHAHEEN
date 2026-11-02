from __future__ import annotations

import sqlite3


def apply_migrations(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("INSERT OR IGNORE INTO schema_migrations(name) VALUES ('initial_schema')")
    conn.commit()
