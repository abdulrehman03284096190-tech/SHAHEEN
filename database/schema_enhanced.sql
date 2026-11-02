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
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT,
    supporting_packets TEXT,
    status TEXT DEFAULT 'new',
    confidence REAL,
    analyst_notes TEXT,
    detection_module TEXT,
    alert_id TEXT,
    evidence TEXT,
    recommendation TEXT,
    FOREIGN KEY(capture_session_id) REFERENCES capture_sessions(id)
);

CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    description TEXT,
    severity TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'Open',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    analyst_notes TEXT
);

CREATE TABLE IF NOT EXISTS investigation_packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id INTEGER,
    packet_id INTEGER,
    added_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    FOREIGN KEY(packet_id) REFERENCES packets(id) ON DELETE CASCADE,
    UNIQUE(investigation_id, packet_id)
);

CREATE TABLE IF NOT EXISTS investigation_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id INTEGER,
    alert_id INTEGER,
    added_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
    UNIQUE(investigation_id, alert_id)
);

CREATE TABLE IF NOT EXISTS analyst_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id INTEGER,
    note TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    author TEXT DEFAULT 'analyst',
    FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS detection_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_session_id INTEGER,
    event_type TEXT,
    details TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(capture_session_id) REFERENCES capture_sessions(id)
);

CREATE TABLE IF NOT EXISTS ip_watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE,
    reason TEXT,
    added_at TEXT DEFAULT CURRENT_TIMESTAMP,
    added_by TEXT DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS detection_configuration (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT UNIQUE,
    enabled INTEGER DEFAULT 1,
    threshold INTEGER,
    config TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
