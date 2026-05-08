CREATE TABLE IF NOT EXISTS url_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    classification TEXT NOT NULL,
    threat_score INTEGER NOT NULL,
    ml_confidence REAL NOT NULL,
    vt_detection_ratio TEXT,
    features_json TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS email_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    subject TEXT,
    extracted_urls TEXT,
    classification TEXT NOT NULL,
    threat_score INTEGER NOT NULL,
    ml_confidence REAL NOT NULL,
    suspicious_terms TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_source TEXT NOT NULL,
    severity TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    ai_confidence REAL NOT NULL,
    scan_source TEXT NOT NULL,
    action_taken TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
