package monitoring

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewNotificationTracker(t *testing.T) {
	tracker := NewNotificationTracker("/tmp/test")
	if tracker == nil {
		t.Fatal("NewNotificationTracker returned nil")
	}
	if tracker.reminderInterval != 24*time.Hour {
		t.Errorf("Expected reminder interval 24h, got %v", tracker.reminderInterval)
	}
}

func TestShouldNotify_FirstTime(t *testing.T) {
	tmpDir := t.TempDir()
	tracker := NewNotificationTracker(tmpDir)

	anomaly := Anomaly{
		Severity: SeverityMedium,
		Category: "services",
		Message:  "New port 9999 detected",
	}

	// First time should notify
	if !tracker.ShouldNotify(anomaly) {
		t.Error("Expected to notify on first anomaly")
	}

	// Second time (immediately) should NOT notify
	if tracker.ShouldNotify(anomaly) {
		t.Error("Expected NOT to notify immediately after first notification")
	}
}

func TestShouldNotify_After24Hours(t *testing.T) {
	tmpDir := t.TempDir()
	tracker := NewNotificationTracker(tmpDir)
	tracker.reminderInterval = 1 * time.Second // Speed up test

	anomaly := Anomaly{
		Severity: SeverityMedium,
		Category: "services",
		Message:  "New port 9999 detected",
	}

	// First notification
	if !tracker.ShouldNotify(anomaly) {
		t.Fatal("Expected first notification")
	}

	// Immediate re-check should skip
	if tracker.ShouldNotify(anomaly) {
		t.Error("Should not notify immediately")
	}

	// Wait for reminder interval
	time.Sleep(1100 * time.Millisecond)

	// Should notify again after interval
	if !tracker.ShouldNotify(anomaly) {
		t.Error("Expected reminder notification after 24h")
	}
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	tracker := NewNotificationTracker(tmpDir)

	anomaly := Anomaly{
		Severity: SeverityHigh,
		Category: "firewall",
		Message:  "Firewall disabled",
	}

	// Create notification record
	tracker.ShouldNotify(anomaly)

	// Save state
	if err := tracker.Save(); err != nil {
		t.Fatalf("Failed to save: %v", err)
	}

	// Verify file exists
	stateFile := filepath.Join(tmpDir, "notification_state.json")
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		t.Fatal("State file was not created")
	}

	// Create new tracker and load state
	tracker2 := NewNotificationTracker(tmpDir)
	if err := tracker2.Load(); err != nil {
		t.Fatalf("Failed to load: %v", err)
	}

	// Should have loaded the record
	if len(tracker2.records) != 1 {
		t.Errorf("Expected 1 record, got %d", len(tracker2.records))
	}

	// Should NOT notify immediately (already tracked)
	if tracker2.ShouldNotify(anomaly) {
		t.Error("Loaded tracker should not notify for already-tracked anomaly")
	}
}

func TestMarkResolved(t *testing.T) {
	tmpDir := t.TempDir()
	tracker := NewNotificationTracker(tmpDir)

	anomaly := Anomaly{
		Severity: SeverityMedium,
		Category: "services",
		Message:  "Port 9999 open",
	}

	// Create record
	tracker.ShouldNotify(anomaly)
	if len(tracker.records) != 1 {
		t.Fatal("Expected 1 record")
	}

	// Mark as resolved
	tracker.MarkResolved(anomaly)
	if len(tracker.records) != 0 {
		t.Error("Expected record to be removed after resolution")
	}

	// Should notify again (fresh start)
	if !tracker.ShouldNotify(anomaly) {
		t.Error("Expected to notify after anomaly was marked resolved")
	}
}

func TestCleanupOldRecords(t *testing.T) {
	tmpDir := t.TempDir()
	tracker := NewNotificationTracker(tmpDir)

	// Create old anomaly
	oldAnomaly := Anomaly{
		Severity: SeverityLow,
		Category: "test",
		Message:  "Old anomaly",
	}
	tracker.ShouldNotify(oldAnomaly)

	// Manually set FirstSeen to 8 days ago
	for _, record := range tracker.records {
		record.FirstSeen = time.Now().Add(-8 * 24 * time.Hour)
	}

	// Create recent anomaly
	recentAnomaly := Anomaly{
		Severity: SeverityLow,
		Category: "test",
		Message:  "Recent anomaly",
	}
	tracker.ShouldNotify(recentAnomaly)

	if len(tracker.records) != 2 {
		t.Fatalf("Expected 2 records, got %d", len(tracker.records))
	}

	// Cleanup records older than 7 days
	tracker.CleanupOldRecords(7 * 24 * time.Hour)

	// Should only have recent record left
	if len(tracker.records) != 1 {
		t.Errorf("Expected 1 record after cleanup, got %d", len(tracker.records))
	}
}

func TestDifferentAnomaliesGetDifferentHashes(t *testing.T) {
	tracker := NewNotificationTracker("/tmp")

	anomaly1 := Anomaly{
		Severity: SeverityMedium,
		Category: "services",
		Message:  "Port 9999 open",
	}

	anomaly2 := Anomaly{
		Severity: SeverityMedium,
		Category: "services",
		Message:  "Port 8888 open",
	}

	hash1 := tracker.hashAnomaly(anomaly1)
	hash2 := tracker.hashAnomaly(anomaly2)

	if hash1 == hash2 {
		t.Error("Different anomalies should have different hashes")
	}
}

func TestSameAnomalyGetsSameHash(t *testing.T) {
	tracker := NewNotificationTracker("/tmp")

	anomaly1 := Anomaly{
		Severity: SeverityMedium,
		Category: "services",
		Message:  "Port 9999 open",
	}

	anomaly2 := Anomaly{
		Severity: SeverityMedium,
		Category: "services",
		Message:  "Port 9999 open",
	}

	hash1 := tracker.hashAnomaly(anomaly1)
	hash2 := tracker.hashAnomaly(anomaly2)

	if hash1 != hash2 {
		t.Error("Same anomaly should have same hash")
	}
}

func TestGetStats(t *testing.T) {
	tmpDir := t.TempDir()
	tracker := NewNotificationTracker(tmpDir)

	stats := tracker.GetStats()
	if stats == nil {
		t.Fatal("GetStats returned nil")
	}

	totalTracked, ok := stats["total_tracked"].(int)
	if !ok {
		t.Error("Expected total_tracked to be int")
	}
	if totalTracked != 0 {
		t.Errorf("Expected 0 tracked, got %d", totalTracked)
	}

	// Add anomaly and check stats
	anomaly := Anomaly{Severity: SeverityMedium, Category: "test", Message: "test"}
	tracker.ShouldNotify(anomaly)

	stats = tracker.GetStats()
	totalTracked = stats["total_tracked"].(int)
	if totalTracked != 1 {
		t.Errorf("Expected 1 tracked after notification, got %d", totalTracked)
	}
}
