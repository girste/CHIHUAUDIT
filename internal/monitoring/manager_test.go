package monitoring

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewMonitoringManager(t *testing.T) {
	logDir := "/tmp/test-monitoring"
	mm := NewMonitoringManager(logDir)

	if mm == nil {
		t.Fatal("NewMonitoringManager returned nil")
	}
	if mm.logDir != logDir {
		t.Errorf("Expected logDir %s, got %s", logDir, mm.logDir)
	}
	expectedPidFile := filepath.Join(logDir, "monitoring.pid")
	if mm.pidFile != expectedPidFile {
		t.Errorf("Expected pidFile %s, got %s", expectedPidFile, mm.pidFile)
	}
}

func TestStatusStruct(t *testing.T) {
	status := Status{
		Running:          true,
		PID:              1234,
		LogDir:           "/var/log/chihuaudit",
		BaselineExists:   true,
		BulletinCount:    5,
		AnomalyCount:     2,
		TotalDiskUsageKB: 1024,
	}

	if !status.Running {
		t.Error("Status should be running")
	}
	if status.PID != 1234 {
		t.Errorf("Expected PID 1234, got %d", status.PID)
	}
	if status.BulletinCount != 5 {
		t.Errorf("Expected 5 bulletins, got %d", status.BulletinCount)
	}
	if status.TotalDiskUsageKB != 1024 {
		t.Errorf("Expected 1024 KB, got %d", status.TotalDiskUsageKB)
	}
}

func TestStartResult(t *testing.T) {
	result := StartResult{
		Success:         true,
		PID:             5678,
		IntervalSeconds: 300,
		LogDir:          "/tmp/logs",
	}

	if !result.Success {
		t.Error("StartResult should be successful")
	}
	if result.PID != 5678 {
		t.Errorf("Expected PID 5678, got %d", result.PID)
	}
	if result.IntervalSeconds != 300 {
		t.Errorf("Expected 300 seconds, got %d", result.IntervalSeconds)
	}
}

func TestStartResultWithError(t *testing.T) {
	result := StartResult{
		Success: false,
		Error:   "failed to start daemon",
	}

	if result.Success {
		t.Error("StartResult should not be successful")
	}
	if result.Error != "failed to start daemon" {
		t.Errorf("Expected error message, got %s", result.Error)
	}
	if result.PID != 0 {
		t.Error("PID should be 0 when failed")
	}
}

func TestStopResult(t *testing.T) {
	result := StopResult{
		Success: true,
	}

	if !result.Success {
		t.Error("StopResult should be successful")
	}
}

func TestMonitoringManager_GetPidFile(t *testing.T) {
	tmpDir := t.TempDir()
	mm := NewMonitoringManager(tmpDir)

	expectedPidFile := filepath.Join(tmpDir, "monitoring.pid")
	if mm.pidFile != expectedPidFile {
		t.Errorf("Expected pidFile %s, got %s", expectedPidFile, mm.pidFile)
	}

	// Test that directory exists
	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		t.Error("Log directory should exist")
	}
}
