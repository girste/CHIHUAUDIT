package monitoring

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// NotificationRecord tracks when an anomaly was last notified
type NotificationRecord struct {
	AnomalyHash  string    `json:"anomaly_hash"`
	FirstSeen    time.Time `json:"first_seen"`
	LastNotified time.Time `json:"last_notified"`
	NotifyCount  int       `json:"notify_count"`
	Severity     string    `json:"severity"`
	Message      string    `json:"message"`
}

// NotificationTracker manages notification state to prevent spam
type NotificationTracker struct {
	stateFile string
	records   map[string]*NotificationRecord
	mu        sync.RWMutex

	// Backoff configuration
	reminderInterval time.Duration // Fixed reminder interval (24h)
}

// NewNotificationTracker creates a new tracker
func NewNotificationTracker(logDir string) *NotificationTracker {
	return &NotificationTracker{
		stateFile:        filepath.Join(logDir, "notification_state.json"),
		records:          make(map[string]*NotificationRecord),
		reminderInterval: 24 * time.Hour, // Fixed 24h reminder
	}
}

// Load loads the notification state from disk
func (nt *NotificationTracker) Load() error {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	data, err := os.ReadFile(nt.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			// First run, no state file yet
			return nil
		}
		return fmt.Errorf("failed to read state file: %w", err)
	}

	var records []*NotificationRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("failed to unmarshal state: %w", err)
	}

	// Convert slice to map
	for _, r := range records {
		nt.records[r.AnomalyHash] = r
	}

	return nil
}

// Save persists the notification state to disk
func (nt *NotificationTracker) Save() error {
	nt.mu.RLock()
	defer nt.mu.RUnlock()

	// Convert map to slice
	records := make([]*NotificationRecord, 0, len(nt.records))
	for _, r := range nt.records {
		records = append(records, r)
	}

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	if err := os.WriteFile(nt.stateFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}

// ShouldNotify checks if an anomaly should trigger a notification
// Returns true if:
// - First time seeing this anomaly
// - Last notification was >= reminderInterval ago (24h)
func (nt *NotificationTracker) ShouldNotify(anomaly Anomaly) bool {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	hash := nt.hashAnomaly(anomaly)
	now := time.Now()

	record, exists := nt.records[hash]
	if !exists {
		// First time seeing this anomaly - notify!
		nt.records[hash] = &NotificationRecord{
			AnomalyHash:  hash,
			FirstSeen:    now,
			LastNotified: now,
			NotifyCount:  1,
			Severity:     anomaly.Severity,
			Message:      anomaly.Message,
		}
		return true
	}

	// Check if enough time has passed for a reminder (24h)
	timeSinceLastNotify := now.Sub(record.LastNotified)
	if timeSinceLastNotify >= nt.reminderInterval {
		// Time for a reminder
		record.LastNotified = now
		record.NotifyCount++
		return true
	}

	// Already notified recently, skip
	return false
}

// MarkResolved removes an anomaly from tracking (it's been fixed)
func (nt *NotificationTracker) MarkResolved(anomaly Anomaly) {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	hash := nt.hashAnomaly(anomaly)
	delete(nt.records, hash)
}

// CleanupOldRecords removes records for anomalies not seen in the last N days
func (nt *NotificationTracker) CleanupOldRecords(maxAge time.Duration) {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	now := time.Now()
	for hash, record := range nt.records {
		if now.Sub(record.FirstSeen) > maxAge {
			delete(nt.records, hash)
		}
	}
}

// hashAnomaly creates a unique hash for an anomaly
// Hash is based on severity + category + core message (without timestamps/PIDs)
func (nt *NotificationTracker) hashAnomaly(anomaly Anomaly) string {
	// Use severity + category + message as hash input
	// This ensures same type of anomaly gets same hash
	hashInput := fmt.Sprintf("%s:%s:%s", anomaly.Severity, anomaly.Category, anomaly.Message)
	hash := sha256.Sum256([]byte(hashInput))
	return fmt.Sprintf("%x", hash[:16]) // Use first 16 bytes for shorter hash
}

// GetStats returns statistics about tracked notifications
func (nt *NotificationTracker) GetStats() map[string]interface{} {
	nt.mu.RLock()
	defer nt.mu.RUnlock()

	return map[string]interface{}{
		"total_tracked":     len(nt.records),
		"reminder_interval": nt.reminderInterval.String(),
	}
}
