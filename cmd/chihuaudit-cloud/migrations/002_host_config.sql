CREATE TABLE IF NOT EXISTS host_config (
    host_id INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    webhook_url TEXT,
    cpu_threshold REAL DEFAULT 60,
    memory_threshold REAL DEFAULT 60,
    disk_threshold REAL DEFAULT 80,
    ignore_changes TEXT DEFAULT '["uptime","active_connections","process_list","network_rx_tx","timestamp","last_seen","last_backup","resources.cpu_percent","resources.mem_percent","resources.load_average","system.pending_updates","logs.syslog_errors","network.latency","storage.disk_io","docker.running","database.active_connections"]',
    retention_count INTEGER DEFAULT 1000,
    updated_at TEXT DEFAULT (datetime('now'))
);
