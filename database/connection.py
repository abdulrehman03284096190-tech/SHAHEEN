from __future__ import annotations

import sqlite3
import json
import logging
from pathlib import Path


DATABASE_SCHEMA_VERSION = 2


def initialize_database(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    schema = """
    CREATE TABLE IF NOT EXISTS capture_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_type TEXT,
        source_path TEXT,
        start_timestamp TEXT,
        end_timestamp TEXT,
        status TEXT,
        packet_count INTEGER DEFAULT 0,
        byte_count INTEGER DEFAULT 0,
        capture_stats TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        capture_session_id INTEGER,
        packet_number INTEGER,
        timestamp TEXT,
        source_address TEXT,
        destination_address TEXT,
        source_port INTEGER,
        destination_port INTEGER,
        protocol TEXT,
        packet_length INTEGER,
        summary TEXT,
        metadata TEXT,
        details TEXT,
        tcp_flags_syn INTEGER NOT NULL DEFAULT 0,
        original_reference TEXT,
        FOREIGN KEY(capture_session_id) REFERENCES capture_sessions(id)
    );

    CREATE TABLE IF NOT EXISTS conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        capture_session_id INTEGER,
        protocol TEXT,
        normalized_endpoints TEXT,
        first_seen TEXT,
        last_seen TEXT,
        packet_count INTEGER,
        byte_count INTEGER,
        directional_stats TEXT,
        FOREIGN KEY(capture_session_id) REFERENCES capture_sessions(id)
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        capture_session_id INTEGER,
        rule_id TEXT,
        timestamp TEXT,
        severity TEXT,
        title TEXT,
        description TEXT,
        source_address TEXT,
        destination_address TEXT,
        supporting_packets TEXT,
        status TEXT,
        confidence REAL,
        analyst_notes TEXT,
        FOREIGN KEY(capture_session_id) REFERENCES capture_sessions(id)
    );

    CREATE TABLE IF NOT EXISTS detection_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        description TEXT,
        rule_type TEXT,
        configuration TEXT,
        enabled INTEGER DEFAULT 1,
        severity TEXT,
        version TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS investigations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        status TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        analyst_notes TEXT
    );

    CREATE TABLE IF NOT EXISTS investigation_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER,
        timestamp TEXT,
        event_type TEXT,
        summary TEXT,
        source_reference TEXT,
        metadata TEXT,
        FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """
    conn.executescript(schema)
    schema_version = conn.execute("PRAGMA user_version").fetchone()[0]
    if schema_version < 2:
        packet_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(packets)").fetchall()
        }
        with conn:
            if "details" not in packet_columns:
                conn.execute("ALTER TABLE packets ADD COLUMN details TEXT")
            if "tcp_flags_syn" not in packet_columns:
                conn.execute(
                    "ALTER TABLE packets ADD COLUMN tcp_flags_syn INTEGER NOT NULL DEFAULT 0"
                )
            rows = conn.execute(
                "SELECT id, metadata FROM packets WHERE metadata IS NOT NULL"
            ).fetchall()
            invalid_metadata_rows = 0
            for row in rows:
                try:
                    syn = int(json.loads(row["metadata"]).get("tcp_flags_syn", 0))
                except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                    syn = 0
                    invalid_metadata_rows += 1
                conn.execute(
                    "UPDATE packets SET tcp_flags_syn = ? WHERE id = ?",
                    (syn, row["id"]),
                )
            if invalid_metadata_rows:
                logging.getLogger(__name__).warning(
                    "Defaulted TCP SYN metadata during migration for %s invalid packet row(s)",
                    invalid_metadata_rows,
                )
            for index_name in (
                "idx_packets_capture_timestamp",
                "idx_packets_capture_protocol",
                "idx_packets_capture_source",
            ):
                conn.execute(f"DROP INDEX IF EXISTS {index_name}")
            conn.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")
    conn.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_packets_capture_timestamp
            ON packets(capture_session_id, timestamp, id);
        CREATE INDEX IF NOT EXISTS idx_packets_capture_protocol
            ON packets(capture_session_id, protocol COLLATE NOCASE, timestamp, id);
        CREATE INDEX IF NOT EXISTS idx_packets_capture_source
            ON packets(capture_session_id, source_address, timestamp, id);
        CREATE INDEX IF NOT EXISTS idx_packets_capture_destination
            ON packets(capture_session_id, destination_address, timestamp, id);
        CREATE INDEX IF NOT EXISTS idx_packets_capture_source_port
            ON packets(capture_session_id, source_port, timestamp, id);
        CREATE INDEX IF NOT EXISTS idx_packets_capture_destination_port
            ON packets(capture_session_id, destination_port, timestamp, id);
        CREATE INDEX IF NOT EXISTS idx_packets_capture_tcp_syn
            ON packets(capture_session_id, tcp_flags_syn, timestamp, id);
        CREATE INDEX IF NOT EXISTS idx_investigation_events_case_time
            ON investigation_events(investigation_id, timestamp, id);
        CREATE INDEX IF NOT EXISTS idx_packets_capture_number
            ON packets(capture_session_id, packet_number);
        CREATE INDEX IF NOT EXISTS idx_alerts_capture_time
            ON alerts(capture_session_id, timestamp);
        """
    )
    return conn
