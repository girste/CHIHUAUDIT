-- Threshold breach tracking (persistent alerts)
CREATE TABLE IF NOT EXISTS threshold_breaches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    metric TEXT NOT NULL,
    threshold_value REAL NOT NULL,
    current_value REAL NOT NULL,
    first_exceeded_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at TEXT,
    alerted_persistent INTEGER DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_threshold_breaches_active
    ON threshold_breaches(host_id, metric) WHERE resolved_at IS NULL;
