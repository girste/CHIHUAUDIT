package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	if cfg == nil {
		t.Fatal("Default() returned nil")
	}

	// Check default values
	if cfg.ThreatAnalysisDays != 7 {
		t.Errorf("ThreatAnalysisDays = %d, want 7", cfg.ThreatAnalysisDays)
	}

	if cfg.AnalyzerTimeout != 10 {
		t.Errorf("AnalyzerTimeout = %d, want 10", cfg.AnalyzerTimeout)
	}

	if !cfg.MaskData {
		t.Error("MaskData should be true by default")
	}

	if cfg.Monitoring.Enabled {
		t.Error("Monitoring.Enabled should be false by default")
	}

	if cfg.Monitoring.IntervalSeconds != 3600 {
		t.Errorf("Monitoring.IntervalSeconds = %d, want 3600", cfg.Monitoring.IntervalSeconds)
	}

	if cfg.Notifications.Enabled {
		t.Error("Notifications.Enabled should be false by default")
	}

	if !cfg.Notifications.OnlyOnIssues {
		t.Error("Notifications.OnlyOnIssues should be true by default")
	}
}

func TestLoad_NoConfigFile(t *testing.T) {
	// Load should return defaults when no config file exists
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg == nil {
		t.Fatal("Load() returned nil")
	}

	// Should have default values
	if cfg.ThreatAnalysisDays != 7 {
		t.Errorf("ThreatAnalysisDays = %d, want 7", cfg.ThreatAnalysisDays)
	}
}

func TestLoad_WithConfigFile(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".mcp-watchdog.yaml")

	configContent := `
threatAnalysisDays: 14
analyzerTimeoutSeconds: 20
maskData: false
monitoring:
  enabled: true
  intervalSeconds: 1800
notifications:
  enabled: true
  minSeverity: "critical"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Change to temp dir so Load() finds the config
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ThreatAnalysisDays != 14 {
		t.Errorf("ThreatAnalysisDays = %d, want 14", cfg.ThreatAnalysisDays)
	}

	if cfg.AnalyzerTimeout != 20 {
		t.Errorf("AnalyzerTimeout = %d, want 20", cfg.AnalyzerTimeout)
	}

	if cfg.MaskData {
		t.Error("MaskData should be false")
	}

	if !cfg.Monitoring.Enabled {
		t.Error("Monitoring.Enabled should be true")
	}

	if cfg.Monitoring.IntervalSeconds != 1800 {
		t.Errorf("Monitoring.IntervalSeconds = %d, want 1800", cfg.Monitoring.IntervalSeconds)
	}
}

func TestIsAnalyzerEnabled(t *testing.T) {
	cfg := Default()

	// Default: all enabled
	if !cfg.IsAnalyzerEnabled("firewall") {
		t.Error("firewall should be enabled by default")
	}

	if !cfg.IsAnalyzerEnabled("ssh") {
		t.Error("ssh should be enabled by default")
	}

	// Unknown analyzer should be enabled by default
	if !cfg.IsAnalyzerEnabled("unknown_analyzer") {
		t.Error("unknown analyzer should be enabled by default")
	}

	// Disable an analyzer
	cfg.Checks["firewall"] = false
	if cfg.IsAnalyzerEnabled("firewall") {
		t.Error("firewall should be disabled")
	}
}

func TestGetMaxConcurrency(t *testing.T) {
	cfg := Default()

	// Default: 0 means auto
	maxConc := cfg.GetMaxConcurrency()
	if maxConc <= 0 {
		t.Errorf("GetMaxConcurrency() = %d, want > 0", maxConc)
	}

	// Set explicit value
	cfg.MaxConcurrency = 4
	if cfg.GetMaxConcurrency() != 4 {
		t.Errorf("GetMaxConcurrency() = %d, want 4", cfg.GetMaxConcurrency())
	}
}
