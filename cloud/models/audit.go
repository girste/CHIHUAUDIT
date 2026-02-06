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
	id, _ := result.LastInsertId()
	a := &Audit{
		ID:        int(id),
		HostID:    hostID,
		Results:   results,
		CreatedAt: time.Now().UTC(),
	}
	return a, nil
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
		a.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		audits = append(audits, a)
	}
	return audits, rows.Err()
}
