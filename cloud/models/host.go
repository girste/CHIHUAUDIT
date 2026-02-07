package models

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

type Host struct {
	ID        int        `json:"id"`
	Name      string     `json:"name"`
	LastSeen  *time.Time `json:"last_seen"`
	CreatedAt time.Time  `json:"created_at"`
}

type HostWithLastAudit struct {
	Host
	LastAuditResults json.RawMessage `json:"last_audit_results,omitempty"`
	LastAuditAt      *time.Time      `json:"last_audit_at,omitempty"`
	AuditCount       int             `json:"audit_count"`
}

var timeFormats = []string{
	time.DateTime,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05",
	time.RFC3339,
}

func parseTime(s string) (time.Time, bool) {
	for _, f := range timeFormats {
		if t, err := time.Parse(f, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func scanTime(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	if t, ok := parseTime(s.String); ok {
		return &t
	}
	return nil
}

func scanTimeValue(s string) time.Time {
	if t, ok := parseTime(s); ok {
		return t
	}
	return time.Time{}
}

func ListHosts() ([]HostWithLastAudit, error) {
	rows, err := DB.Query(`
		SELECT h.id, h.name, h.last_seen, h.created_at,
			(SELECT results FROM audits WHERE host_id = h.id ORDER BY created_at DESC LIMIT 1) as last_results,
			(SELECT created_at FROM audits WHERE host_id = h.id ORDER BY created_at DESC LIMIT 1) as audit_at,
			(SELECT count(*) FROM audits WHERE host_id = h.id) as audit_count
		FROM hosts h
		ORDER BY h.name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []HostWithLastAudit
	for rows.Next() {
		var h HostWithLastAudit
		var lastSeen, createdAt, auditAt sql.NullString
		var results sql.NullString
		err := rows.Scan(&h.ID, &h.Name, &lastSeen, &createdAt,
			&results, &auditAt, &h.AuditCount)
		if err != nil {
			return nil, err
		}
		h.LastSeen = scanTime(lastSeen)
		h.CreatedAt = scanTimeValue(createdAt.String)
		if results.Valid {
			h.LastAuditResults = json.RawMessage(results.String)
		}
		h.LastAuditAt = scanTime(auditAt)
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

func GetHost(id int) (*Host, error) {
	h := &Host{}
	var lastSeen, createdAt sql.NullString
	err := DB.QueryRow(
		"SELECT id, name, last_seen, created_at FROM hosts WHERE id = ?", id,
	).Scan(&h.ID, &h.Name, &lastSeen, &createdAt)
	if err != nil {
		return nil, err
	}
	h.LastSeen = scanTime(lastSeen)
	h.CreatedAt = scanTimeValue(createdAt.String)
	return h, nil
}

func GetHostByAPIKey(apiKey string) (*Host, error) {
	hash := HashAPIKey(apiKey)
	h := &Host{}
	var lastSeen, createdAt sql.NullString
	err := DB.QueryRow(
		"SELECT id, name, last_seen, created_at FROM hosts WHERE api_key_hash = ?", hash,
	).Scan(&h.ID, &h.Name, &lastSeen, &createdAt)
	if err != nil {
		return nil, err
	}
	h.LastSeen = scanTime(lastSeen)
	h.CreatedAt = scanTimeValue(createdAt.String)
	return h, nil
}

func CreateHost(name, apiKey string) (*Host, error) {
	hash := HashAPIKey(apiKey)
	result, err := DB.Exec(
		"INSERT INTO hosts (name, api_key_hash) VALUES (?, ?)",
		name, hash,
	)
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("last insert id: %w", err)
	}
	h := &Host{
		ID:        int(id),
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}
	return h, nil
}

func UpdateHostLastSeen(id int) error {
	_, err := DB.Exec("UPDATE hosts SET last_seen = datetime('now') WHERE id = ?", id)
	return err
}

type HostConfig struct {
	HostID          int      `json:"host_id"`
	WebhookURL      string   `json:"webhook_url"`
	CPUThreshold    float64  `json:"cpu_threshold"`
	MemoryThreshold float64  `json:"memory_threshold"`
	DiskThreshold   float64  `json:"disk_threshold"`
	IgnoreChanges   []string `json:"ignore_changes"`
	RetentionDays   int      `json:"retention_days"`
}

func GetHostConfig(hostID int) (*HostConfig, error) {
	cfg := &HostConfig{
		HostID:          hostID,
		CPUThreshold:    60,
		MemoryThreshold: 60,
		DiskThreshold:   80,
		RetentionDays:   90,
		IgnoreChanges:   []string{"uptime", "active_connections", "process_list", "network_rx_tx"},
	}

	var ignoreJSON sql.NullString
	err := DB.QueryRow(
		`SELECT webhook_url, cpu_threshold, memory_threshold, disk_threshold, ignore_changes, COALESCE(retention_days, 90)
		 FROM host_config WHERE host_id = ?`, hostID,
	).Scan(&cfg.WebhookURL, &cfg.CPUThreshold, &cfg.MemoryThreshold, &cfg.DiskThreshold, &ignoreJSON, &cfg.RetentionDays)
	if err != nil {
		if err == sql.ErrNoRows {
			return cfg, nil
		}
		return nil, err
	}

	if ignoreJSON.Valid && ignoreJSON.String != "" {
		cfg.IgnoreChanges = parseJSONArray(ignoreJSON.String)
	}
	return cfg, nil
}

func UpdateHostConfig(cfg *HostConfig) error {
	ignoreJSON, _ := json.Marshal(cfg.IgnoreChanges)
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 90
	}
	_, err := DB.Exec(`
		INSERT INTO host_config (host_id, webhook_url, cpu_threshold, memory_threshold, disk_threshold, ignore_changes, retention_days, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT (host_id) DO UPDATE SET
			webhook_url = excluded.webhook_url,
			cpu_threshold = excluded.cpu_threshold,
			memory_threshold = excluded.memory_threshold,
			disk_threshold = excluded.disk_threshold,
			ignore_changes = excluded.ignore_changes,
			retention_days = excluded.retention_days,
			updated_at = datetime('now')`,
		cfg.HostID, cfg.WebhookURL, cfg.CPUThreshold, cfg.MemoryThreshold, cfg.DiskThreshold, string(ignoreJSON), cfg.RetentionDays,
	)
	return err
}

func GetPreviousAuditResults(hostID int) (json.RawMessage, error) {
	var results string
	err := DB.QueryRow(
		`SELECT results FROM audits WHERE host_id = ? ORDER BY created_at DESC LIMIT 1 OFFSET 1`,
		hostID,
	).Scan(&results)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return json.RawMessage(results), nil
}

func parseJSONArray(s string) []string {
	var arr []string
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		return nil
	}
	return arr
}

func HashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func RotateHostAPIKey(hostID int, newHash string) error {
	result, err := DB.Exec("UPDATE hosts SET api_key_hash = ? WHERE id = ?", newHash, hostID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func CleanupOldAudits() {
	result, err := DB.Exec(`
		DELETE FROM audits WHERE id IN (
			SELECT a.id FROM audits a
			JOIN hosts h ON a.host_id = h.id
			LEFT JOIN host_config c ON c.host_id = h.id
			WHERE a.created_at < datetime('now', '-' || COALESCE(c.retention_days, 90) || ' days')
		)
	`)
	if err != nil {
		log.Printf("cleanup old audits error: %v", err)
		return
	}
	rows, _ := result.RowsAffected()
	if rows > 0 {
		log.Printf("cleanup: deleted %d old audits", rows)
	}
}

type ThresholdBreach struct {
	ID                int        `json:"id"`
	HostID            int        `json:"host_id"`
	Metric            string     `json:"metric"`
	ThresholdValue    float64    `json:"threshold_value"`
	CurrentValue      float64    `json:"current_value"`
	FirstExceededAt   time.Time  `json:"first_exceeded_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	ResolvedAt        *time.Time `json:"resolved_at,omitempty"`
	AlertedPersistent bool       `json:"alerted_persistent"`
}

func UpsertThresholdBreach(hostID int, metric string, threshold, value float64) error {
	_, err := DB.Exec(`
		INSERT INTO threshold_breaches (host_id, metric, threshold_value, current_value, first_exceeded_at, last_seen_at)
		VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
		ON CONFLICT (host_id, metric) WHERE resolved_at IS NULL
		DO UPDATE SET current_value = ?, last_seen_at = datetime('now')`,
		hostID, metric, threshold, value, value,
	)
	return err
}

func ResolveThresholdBreach(hostID int, metric string) error {
	_, err := DB.Exec(`
		UPDATE threshold_breaches SET resolved_at = datetime('now')
		WHERE host_id = ? AND metric = ? AND resolved_at IS NULL`,
		hostID, metric,
	)
	return err
}

type PendingPersistentAlert struct {
	ThresholdBreach
	HostName   string `json:"host_name"`
	WebhookURL string `json:"webhook_url"`
}

func GetPendingPersistentAlerts(minDuration time.Duration) ([]PendingPersistentAlert, error) {
	hours := int(minDuration.Hours())
	rows, err := DB.Query(`
		SELECT tb.id, tb.host_id, tb.metric, tb.threshold_value, tb.current_value,
		       tb.first_exceeded_at, tb.last_seen_at, h.name,
		       COALESCE(c.webhook_url, '')
		FROM threshold_breaches tb
		JOIN hosts h ON h.id = tb.host_id
		LEFT JOIN host_config c ON c.host_id = tb.host_id
		WHERE tb.resolved_at IS NULL
		  AND tb.alerted_persistent = 0
		  AND tb.first_exceeded_at < datetime('now', ? || ' hours')`,
		-hours,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []PendingPersistentAlert
	for rows.Next() {
		var a PendingPersistentAlert
		var firstExceeded, lastSeen string
		err := rows.Scan(&a.ID, &a.HostID, &a.Metric, &a.ThresholdValue, &a.CurrentValue,
			&firstExceeded, &lastSeen, &a.HostName, &a.WebhookURL)
		if err != nil {
			return nil, err
		}
		a.FirstExceededAt = scanTimeValue(firstExceeded)
		a.LastSeenAt = scanTimeValue(lastSeen)
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func MarkPersistentAlerted(breachID int) error {
	_, err := DB.Exec("UPDATE threshold_breaches SET alerted_persistent = 1 WHERE id = ?", breachID)
	return err
}

// RecentAlerts returns unresolved threshold breaches with host names.
type RecentAlert struct {
	ID             int       `json:"id"`
	HostID         int       `json:"host_id"`
	HostName       string    `json:"host_name"`
	Metric         string    `json:"metric"`
	ThresholdValue float64   `json:"threshold_value"`
	CurrentValue   float64   `json:"current_value"`
	FirstExceeded  time.Time `json:"first_exceeded_at"`
	LastSeen       time.Time `json:"last_seen_at"`
}

func GetRecentAlerts(limit int) ([]RecentAlert, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := DB.Query(`
		SELECT tb.id, tb.host_id, h.name, tb.metric, tb.threshold_value, tb.current_value,
		       tb.first_exceeded_at, tb.last_seen_at
		FROM threshold_breaches tb
		JOIN hosts h ON h.id = tb.host_id
		WHERE tb.resolved_at IS NULL
		ORDER BY tb.last_seen_at DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []RecentAlert
	for rows.Next() {
		var a RecentAlert
		var first, last string
		err := rows.Scan(&a.ID, &a.HostID, &a.HostName, &a.Metric, &a.ThresholdValue, &a.CurrentValue, &first, &last)
		if err != nil {
			return nil, err
		}
		a.FirstExceeded = scanTimeValue(first)
		a.LastSeen = scanTimeValue(last)
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// GetHostAlerts returns unresolved alerts for a specific host.
func GetHostAlerts(hostID int) ([]RecentAlert, error) {
	rows, err := DB.Query(`
		SELECT tb.id, tb.host_id, h.name, tb.metric, tb.threshold_value, tb.current_value,
		       tb.first_exceeded_at, tb.last_seen_at
		FROM threshold_breaches tb
		JOIN hosts h ON h.id = tb.host_id
		WHERE tb.resolved_at IS NULL AND tb.host_id = ?
		ORDER BY tb.last_seen_at DESC`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []RecentAlert
	for rows.Next() {
		var a RecentAlert
		var first, last string
		err := rows.Scan(&a.ID, &a.HostID, &a.HostName, &a.Metric, &a.ThresholdValue, &a.CurrentValue, &first, &last)
		if err != nil {
			return nil, err
		}
		a.FirstExceeded = scanTimeValue(first)
		a.LastSeen = scanTimeValue(last)
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// DeleteHost deletes a host and its related data (all FKs have ON DELETE CASCADE).
func DeleteHost(id int) (int64, error) {
	result, err := DB.Exec("DELETE FROM hosts WHERE id = ?", id)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
