-- Security and configuration change alerts
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    description TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    severity TEXT DEFAULT 'warning' CHECK(severity IN ('info', 'warning', 'critical')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at TEXT,
    acknowledged INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alerts_host_unresolved 
    ON alerts(host_id, created_at DESC) WHERE resolved_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_alerts_created 
    ON alerts(created_at DESC);
