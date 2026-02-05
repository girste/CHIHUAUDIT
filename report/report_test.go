package report

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"chihuaudit/checks"
)

func TestPrintJSON(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	results := &checks.AuditResults{
		Timestamp: time.Now(),
		Hostname:  "test-host",
		OS:        "Ubuntu 24.04",
		Kernel:    "6.5.0",
		Uptime:    "1h",
	}

	PrintJSON(results)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	// Verify it's valid JSON
	var decoded checks.AuditResults
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Errorf("PrintJSON output is not valid JSON: %v", err)
	}

	if decoded.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want %q", decoded.Hostname, "test-host")
	}
}

func TestPrintText(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	results := &checks.AuditResults{
		Timestamp: time.Now(),
		Hostname:  "test-host",
		OS:        "Ubuntu 24.04",
		Kernel:    "6.5.0",
		Uptime:    "1h",
		Security: checks.Security{
			Firewall:   "ufw",
			SSHStatus:  "active",
			OpenPorts:  []int{22, 80, 443},
		},
		Services: checks.Services{
			TotalRunning: 10,
			Failed:       1,
		},
		Resources: checks.Resources{
			CPUPercent: 25.5,
			MemPercent: 45.2,
		},
	}

	PrintText(results)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	output := buf.String()

	// Verify key elements are present
	if !contains(output, "CHIHUAUDIT REPORT") {
		t.Error("Output missing 'CHIHUAUDIT REPORT'")
	}
	if !contains(output, "test-host") {
		t.Error("Output missing hostname")
	}
	if !contains(output, "SECURITY") {
		t.Error("Output missing SECURITY section")
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
