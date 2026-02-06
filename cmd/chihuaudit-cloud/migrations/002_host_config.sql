CREATE TABLE IF NOT EXISTS host_config (
    host_id INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    webhook_url TEXT,
    cpu_threshold REAL DEFAULT 60,
    memory_threshold REAL DEFAULT 60,
    disk_threshold REAL DEFAULT 80,
    ignore_changes TEXT DEFAULT '["uptime","active_connections","process_list","network_rx_tx"]',
    retention_days INTEGER DEFAULT 90,
    updated_at TEXT DEFAULT (datetime('now'))
);
