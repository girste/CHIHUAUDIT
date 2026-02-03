package monitoring

import (
	"testing"
)

func TestNewDriftMonitor(t *testing.T) {
	logDir := "/tmp/test-drift"
	dm := NewDriftMonitor(logDir, true)

	if dm == nil {
		t.Fatal("NewDriftMonitor returned nil")
	}
	if dm.logDir != logDir {
		t.Errorf("Expected logDir %s, got %s", logDir, dm.logDir)
	}
	if !dm.verbose {
		t.Error("Verbose should be true")
	}
	if dm.logger == nil {
		t.Error("Logger should not be nil")
	}
}

func TestDriftResult(t *testing.T) {
	result := DriftResult{
		Status:       "drift_detected",
		DriftCount:   5,
		BulletinFile: "/tmp/bulletin.json",
		AnomalyFile:  "/tmp/anomaly.json",
	}

	if result.Status != "drift_detected" {
		t.Errorf("Expected status drift_detected, got %s", result.Status)
	}
	if result.DriftCount != 5 {
		t.Errorf("Expected 5 drifts, got %d", result.DriftCount)
	}
	if result.BulletinFile == "" {
		t.Error("BulletinFile should not be empty")
	}
}

func TestDriftResultNoDrift(t *testing.T) {
	result := DriftResult{
		Status:     "no_drift",
		DriftCount: 0,
	}

	if result.Status != "no_drift" {
		t.Error("Status should be no_drift")
	}
	if result.DriftCount != 0 {
		t.Error("DriftCount should be 0")
	}
	if result.BulletinFile != "" {
		t.Error("BulletinFile should be empty when no drift")
	}
}
