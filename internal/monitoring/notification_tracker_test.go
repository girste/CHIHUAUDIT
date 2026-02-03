package monitoring

import (
"testing"
"time"

"github.com/girste/chihuaudit/internal/alertcodes"
"github.com/girste/chihuaudit/internal/analyzers"
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

alert := alertcodes.Alert{
Severity: analyzers.SeverityMedium,
Analyzer: "services",
Message:  "New port 9999 detected",
}

if !tracker.ShouldNotify(alert) {
t.Error("Expected to notify on first alert")
}

if tracker.ShouldNotify(alert) {
t.Error("Expected NOT to notify immediately after first notification")
}
}

func TestShouldNotify_After24Hours(t *testing.T) {
tmpDir := t.TempDir()
tracker := NewNotificationTracker(tmpDir)
tracker.reminderInterval = 1 * time.Second

alert := alertcodes.Alert{
Severity: analyzers.SeverityMedium,
Analyzer: "services",
Message:  "New port 9999 detected",
}

if !tracker.ShouldNotify(alert) {
t.Error("Expected to notify first time")
}

time.Sleep(2 * time.Second)

if !tracker.ShouldNotify(alert) {
t.Error("Expected to notify after interval")
}
}

func TestMarkResolved(t *testing.T) {
tmpDir := t.TempDir()
tracker := NewNotificationTracker(tmpDir)

alert := alertcodes.Alert{
Severity: analyzers.SeverityMedium,
Analyzer: "services",
Message:  "Test alert",
}

tracker.ShouldNotify(alert)
tracker.MarkResolved(alert)

if !tracker.ShouldNotify(alert) {
t.Error("Expected to notify again after resolve")
}
}

func TestSaveLoad(t *testing.T) {
tmpDir := t.TempDir()
tracker := NewNotificationTracker(tmpDir)

alert := alertcodes.Alert{
Severity: analyzers.SeverityHigh,
Analyzer: "firewall",
Message:  "Rule changed",
}

tracker.ShouldNotify(alert)

if err := tracker.Save(); err != nil {
t.Fatalf("Save failed: %v", err)
}

tracker2 := NewNotificationTracker(tmpDir)
if err := tracker2.Load(); err != nil {
t.Fatalf("Load failed: %v", err)
}

if tracker2.ShouldNotify(alert) {
t.Error("Loaded tracker should not notify for already-tracked alert")
}
}
