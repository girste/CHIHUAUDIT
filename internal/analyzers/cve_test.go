package analyzers

import (
	"context"
	"testing"
	"time"

	"github.com/girste/chihuaudit/internal/config"
)

func TestCVEAnalyzer_Name(t *testing.T) {
	analyzer := &CVEAnalyzer{}
	if analyzer.Name() != "cve" {
		t.Errorf("Expected name 'cve', got '%s'", analyzer.Name())
	}
}

func TestCVEAnalyzer_RequiresSudo(t *testing.T) {
	analyzer := &CVEAnalyzer{}
	if analyzer.RequiresSudo() {
		t.Error("CVEAnalyzer should not require sudo")
	}
}

func TestCVEAnalyzer_Timeout(t *testing.T) {
	analyzer := &CVEAnalyzer{}
	timeout := analyzer.Timeout()
	if timeout != 60*time.Second {
		t.Errorf("Expected timeout 60s, got %v", timeout)
	}
}

func TestCVEAnalyzer_Analyze(t *testing.T) {
	analyzer := &CVEAnalyzer{}
	cfg := &config.Config{}

	// Short timeout to avoid waiting for actual API calls
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := analyzer.Analyze(ctx, cfg)
	// Error might occur if no package manager found - that's OK
	if err != nil {
		t.Logf("Analyze returned error (expected in minimal env): %v", err)
	}

	// Result should still be returned even on error
	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if !result.Checked {
		t.Error("Result should be marked as checked")
	}

	if result.Data == nil {
		t.Fatal("Result data should not be nil")
	}

	// Verify data structure - Data is already map[string]interface{}
	if _, ok := result.Data["scanned"]; !ok {
		t.Error("Missing 'scanned' field")
	}

	if _, ok := result.Data["vulnerabilities"]; !ok {
		t.Error("Missing 'vulnerabilities' field")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", "critical"},
		{"High", "high"},
		{"MEDIUM", "medium"},
		{"moderate", "medium"},
		{"Low", "low"},
		{"unknown", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		result := normalizeSeverity(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a very long string that should be truncated", 20, "this is a very lo..."},
		{"exact", 5, "exact"},
		{"toolong", 5, "to..."},
	}

	for _, tt := range tests {
		result := truncateString(tt.input, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
		}
	}
}

func TestAffectsVersion(t *testing.T) {
	tests := []struct {
		version     string
		description string
		expected    bool
	}{
		{"1.2.3", "Affects version 1.2.3 and earlier", true},
		{"2.0.0", "Affects all versions", true},
		{"1.5.0", "Fixed in version 1.6.0", false},
		{"1.0.0", "No version information", false},
	}

	for _, tt := range tests {
		result := affectsVersion(tt.version, tt.description)
		if result != tt.expected {
			t.Errorf("affectsVersion(%q, %q) = %v, want %v", tt.version, tt.description, result, tt.expected)
		}
	}
}

func TestGetInstalledPackages(t *testing.T) {
	ctx := context.Background()
	
	packages, err := getInstalledPackages(ctx)
	
	// Should either succeed or return error if no package manager found
	if err != nil && err.Error() != "no supported package manager found" {
		t.Errorf("Unexpected error: %v", err)
	}
	
	// If succeeded, should have some packages
	if err == nil && len(packages) == 0 {
		t.Log("Warning: No packages found, but this might be expected in minimal environment")
	}
}
