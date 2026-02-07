-- Migrate existing databases from retention_days to retention_count
-- This migration handles the upgrade path for existing installations
-- Fresh installs will have retention_count from migration 002

-- Check if old column exists, if so migrate
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pragma_table_info('host_config') WHERE name = 'retention_days') THEN
        -- Recreate table with new column
        CREATE TABLE host_config_new (
            host_id INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
            webhook_url TEXT,
            cpu_threshold REAL DEFAULT 60,
            memory_threshold REAL DEFAULT 60,
            disk_threshold REAL DEFAULT 80,
            ignore_changes TEXT DEFAULT '["uptime","active_connections","process_list","network_rx_tx"]',
            retention_count INTEGER DEFAULT 1000,
            updated_at TEXT DEFAULT (datetime('now'))
        );
        
        -- Copy data
        INSERT INTO host_config_new SELECT host_id, webhook_url, cpu_threshold, memory_threshold, disk_threshold, ignore_changes, 
            retention_days * 10, updated_at FROM host_config;
        
        DROP TABLE host_config;
        ALTER TABLE host_config_new RENAME TO host_config;
    END IF;
END $$;
