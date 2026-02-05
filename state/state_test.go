package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"chihuaudit/checks"
	"chihuaudit/config"
)

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "state.json")

	// Save state
	results := &checks.AuditResults{
		Timestamp: time.Now(),
		Hostname:  "test-host",
		OS:        "Ubuntu",
		Kernel:    "6.5.0",
		Resources: checks.Resources{
			CPUPercent: 50.0,
			MemPercent: 60.0,
		},
	}

	data, _ := json.Marshal(results)
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Load state
	loaded, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	var decoded checks.AuditResults
	if err := json.Unmarshal(loaded, &decoded); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if decoded.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want %q", decoded.Hostname, "test-host")
	}
	if decoded.Resources.CPUPercent != 50.0 {
		t.Errorf("CPUPercent = %v, want 50.0", decoded.Resources.CPUPercent)
	}
}

func TestCompareCPU(t *testing.T) {
	cfg := &config.Config{
		NotificationFilters: config.NotificationFilters{
			CPUThreshold: 60.0,
		},
	}

	tests := []struct {
		name     string
		prev     checks.Resources
		curr     checks.Resources
		wantNil  bool
	}{
		{
			name:    "below threshold to above",
			prev:    checks.Resources{CPUPercent: 50.0},
			curr:    checks.Resources{CPUPercent: 70.0},
			wantNil: false,
		},
		{
			name:    "both below threshold",
			prev:    checks.Resources{CPUPercent: 50.0},
			curr:    checks.Resources{CPUPercent: 55.0},
			wantNil: true,
		},
		{
			name:    "both above threshold",
			prev:    checks.Resources{CPUPercent: 70.0},
			curr:    checks.Resources{CPUPercent: 75.0},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareCPU(tt.prev, tt.curr, cfg)
			if (result == nil) != tt.wantNil {
				t.Errorf("compareCPU() = %v, wantNil = %v", result, tt.wantNil)
			}
			if result != nil && result.Key != "cpu_usage" {
				t.Errorf("Key = %q, want %q", result.Key, "cpu_usage")
			}
		})
	}
}

func TestCompareMemory(t *testing.T) {
	cfg := &config.Config{
		NotificationFilters: config.NotificationFilters{
			MemoryThreshold: 60.0,
		},
	}

	tests := []struct {
		name     string
		prev     checks.Resources
		curr     checks.Resources
		wantNil  bool
	}{
		{
			name:    "below threshold to above",
			prev:    checks.Resources{MemPercent: 50.0},
			curr:    checks.Resources{MemPercent: 70.0},
			wantNil: false,
		},
		{
			name:    "both below threshold",
			prev:    checks.Resources{MemPercent: 50.0},
			curr:    checks.Resources{MemPercent: 55.0},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareMemory(tt.prev, tt.curr, cfg)
			if (result == nil) != tt.wantNil {
				t.Errorf("compareMemory() = %v, wantNil = %v", result, tt.wantNil)
			}
			if result != nil && result.Key != "memory_usage" {
				t.Errorf("Key = %q, want %q", result.Key, "memory_usage")
			}
		})
	}
}

func TestCompareDisk(t *testing.T) {
	cfg := &config.Config{
		NotificationFilters: config.NotificationFilters{
			DiskThreshold: 80.0,
		},
	}

	tests := []struct {
		name     string
		prev     checks.Resources
		curr     checks.Resources
		wantNil  bool
	}{
		{
			name: "below threshold to above",
			prev: checks.Resources{
				DiskMounts: []checks.DiskMount{{Path: "/", Percent: 70.0}},
			},
			curr: checks.Resources{
				DiskMounts: []checks.DiskMount{{Path: "/", Percent: 85.0}},
			},
			wantNil: false,
		},
		{
			name: "both below threshold",
			prev: checks.Resources{
				DiskMounts: []checks.DiskMount{{Path: "/", Percent: 70.0}},
			},
			curr: checks.Resources{
				DiskMounts: []checks.DiskMount{{Path: "/", Percent: 75.0}},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareDisk(tt.prev, tt.curr, cfg)
			if (result == nil) != tt.wantNil {
				t.Errorf("compareDisk() = %v, wantNil = %v", result, tt.wantNil)
			}
			if result != nil && result.Key != "disk_usage" {
				t.Errorf("Key = %q, want %q", result.Key, "disk_usage")
			}
		})
	}
}

func TestCompare(t *testing.T) {
	cfg := &config.Config{
		NotificationFilters: config.NotificationFilters{
			CPUThreshold:    60.0,
			MemoryThreshold: 60.0,
			DiskThreshold:   80.0,
			IgnoreChanges:   []string{},
		},
	}

	prev := &checks.AuditResults{
		Resources: checks.Resources{
			CPUPercent: 50.0,
			MemPercent: 50.0,
		},
		Security: checks.Security{
			Firewall: "ufw",
		},
	}

	curr := &checks.AuditResults{
		Resources: checks.Resources{
			CPUPercent: 70.0,
			MemPercent: 50.0,
		},
		Security: checks.Security{
			Firewall: "iptables",
		},
	}

	changes := Compare(prev, curr, cfg)

	// Should detect CPU and Firewall changes
	if len(changes) < 2 {
		t.Errorf("Compare() found %d changes, want at least 2", len(changes))
	}

	foundCPU := false
	foundFirewall := false
	for _, change := range changes {
		if change.Key == "cpu_usage" {
			foundCPU = true
		}
		if change.Key == "firewall" {
			foundFirewall = true
		}
	}

	if !foundCPU {
		t.Error("Compare() did not detect CPU change")
	}
	if !foundFirewall {
		t.Error("Compare() did not detect firewall change")
	}
}

func TestCompare_NilPrevious(t *testing.T) {
	cfg := &config.Config{
		NotificationFilters: config.DefaultFilters,
	}

	curr := &checks.AuditResults{
		Resources: checks.Resources{
			CPUPercent: 70.0,
		},
	}

	changes := Compare(nil, curr, cfg)

	if len(changes) != 0 {
		t.Errorf("Compare() with nil previous = %d changes, want 0", len(changes))
	}
}
