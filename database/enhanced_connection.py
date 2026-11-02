from __future__ import annotations

import sqlite3
import json
import logging
from pathlib import Path

DATABASE_SCHEMA_VERSION = 3


def initialize_enhanced_database(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    
    schema_file = Path(__file__).parent / "schema_enhanced.sql"
    if schema_file.exists():
        with open(schema_file, 'r') as f:
            schema = f.read()
    else:
        # Fallback schema
        schema = ""
    
    conn.executescript(schema)
    
    # Migrate from old schema if needed
    schema_version = conn.execute("PRAGMA user_version").fetchone()[0]
    if schema_version < 3:
        # Add missing columns to alerts if they don't exist
        alert_cols = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        with conn:
            if "source_port" not in alert_cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN source_port INTEGER")
            if "destination_port" not in alert_cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN destination_port INTEGER")
            if "protocol" not in alert_cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN protocol TEXT")
            if "detection_module" not in alert_cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN detection_module TEXT")
            if "alert_id" not in alert_cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN alert_id TEXT")
            if "evidence" not in alert_cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN evidence TEXT")
            if "recommendation" not in alert_cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN recommendation TEXT")
            if "confidence" not in alert_cols and "confidence" not in alert_cols:
                pass  # might exist
        conn.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")
    
    # Create indexes
    conn.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_packets_capture_timestamp ON packets(capture_session_id, timestamp, id);
        CREATE INDEX IF NOT EXISTS idx_packets_capture_protocol ON packets(capture_session_id, protocol COLLATE NOCASE, timestamp, id);
        CREATE INDEX IF NOT EXISTS idx_packets_capture_source ON packets(capture_session_id, source_address, timestamp, id);
        CREATE INDEX IF NOT EXISTS idx_packets_capture_destination ON packets(capture_session_id, destination_address, timestamp, id);
        CREATE INDEX IF NOT EXISTS idx_alerts_capture_time ON alerts(capture_session_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_watchlist_ip ON ip_watchlist(ip_address);
        """
    )
    return conn
