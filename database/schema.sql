CREATE TABLE IF NOT EXISTS capture_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT,
    source_path TEXT,
    start_timestamp TEXT,
    end_timestamp TEXT,
    status TEXT,
    packet_count INTEGER,
    byte_count INTEGER,
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
    original_reference TEXT
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
