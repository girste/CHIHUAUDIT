-- Recreate audits table with ON DELETE CASCADE
-- SQLite doesn't support ALTER TABLE to add FK constraints, so we recreate
CREATE TABLE IF NOT EXISTS audits_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    results TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO audits_new SELECT * FROM audits;
DROP TABLE IF EXISTS audits;
ALTER TABLE audits_new RENAME TO audits;

CREATE INDEX IF NOT EXISTS idx_audits_host_id ON audits(host_id);
CREATE INDEX IF NOT EXISTS idx_audits_created_at ON audits(created_at);
