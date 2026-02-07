package models

import (
	"encoding/json"
	"time"
)

type Audit struct {
	ID        int             `json:"id"`
	HostID    int             `json:"host_id"`
	Results   json.RawMessage `json:"results"`
	CreatedAt time.Time       `json:"created_at"`
}

func CreateAudit(hostID int, results json.RawMessage) (*Audit, error) {
	result, err := DB.Exec(
		"INSERT INTO audits (host_id, results) VALUES (?, ?)",
		hostID, string(results),
	)
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	a := &Audit{
		ID:        int(id),
		HostID:    hostID,
		Results:   results,
		CreatedAt: time.Now().UTC(),
	}
	return a, nil
}

// MetricPoint is a single data point for performance charts.
type MetricPoint struct {
	Timestamp  time.Time `json:"timestamp"`
	CPUPercent float64   `json:"cpu_percent"`
	MemPercent float64   `json:"mem_percent"`
	DiskPercent float64  `json:"disk_percent"`
}

// GetHostMetrics extracts CPU/mem/disk from the last N audits for charting.
func GetHostMetrics(hostID int, limit int) ([]MetricPoint, error) {
	if limit <= 0 {
		limit = 30
	}
	rows, err := DB.Query(
		"SELECT results, created_at FROM audits WHERE host_id = ? ORDER BY created_at DESC LIMIT ?",
		hostID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []MetricPoint
	for rows.Next() {
		var resultsStr, createdAt string
		if err := rows.Scan(&resultsStr, &createdAt); err != nil {
			return nil, err
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(resultsStr), &data); err != nil {
			continue
		}
		p := MetricPoint{Timestamp: scanTimeValue(createdAt)}
		if res, ok := data["resources"].(map[string]interface{}); ok {
			if v, ok := res["cpu_percent"].(float64); ok {
				p.CPUPercent = v
			}
			if v, ok := res["mem_percent"].(float64); ok {
				p.MemPercent = v
			}
		}
		if stor, ok := data["storage"].(map[string]interface{}); ok {
			if disks, ok := stor["disks"].([]interface{}); ok && len(disks) > 0 {
				if d, ok := disks[0].(map[string]interface{}); ok {
					if v, ok := d["use_percent"].(float64); ok {
						p.DiskPercent = v
					}
				}
			}
			// Fallback: disk_percent at storage level
			if p.DiskPercent == 0 {
				if v, ok := stor["disk_percent"].(float64); ok {
					p.DiskPercent = v
				}
			}
		}
		points = append(points, p)
	}
	// Reverse to chronological order
	for i, j := 0, len(points)-1; i < j; i, j = i+1, j-1 {
		points[i], points[j] = points[j], points[i]
	}
	return points, rows.Err()
}

// GetLatestAuditKeys returns all top-level keys from the latest audit for a host.
func GetLatestAuditKeys(hostID int) ([]string, error) {
	var resultsStr string
	err := DB.QueryRow(
		"SELECT results FROM audits WHERE host_id = ? ORDER BY created_at DESC LIMIT 1",
		hostID,
	).Scan(&resultsStr)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(resultsStr), &data); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	return keys, nil
}

func ListAuditsByHost(hostID int, limit int) ([]Audit, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := DB.Query(
		"SELECT id, host_id, results, created_at FROM audits WHERE host_id = ? ORDER BY created_at DESC LIMIT ?",
		hostID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var audits []Audit
	for rows.Next() {
		var a Audit
		var results string
		var createdAt string
		if err := rows.Scan(&a.ID, &a.HostID, &results, &createdAt); err != nil {
			return nil, err
		}
		a.Results = json.RawMessage(results)
		a.CreatedAt = scanTimeValue(createdAt)
		audits = append(audits, a)
	}
	return audits, rows.Err()
}
