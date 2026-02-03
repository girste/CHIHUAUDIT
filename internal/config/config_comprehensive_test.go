package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Test Load with MCP_CONFIG_DIR environment variable
func TestLoadWithMCPConfigDir(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ".chihuaudit.yaml")
	
	// Create test config
	configYAML := `
notifications:
  enabled: true
  minSeverity: "medium"
  discord:
    enabled: true
    webhookUrl: "https://discord.com/api/webhooks/test"
monitoring:
  intervalSeconds: 600
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0600); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}
	
	// Set environment variable
	_ = os.Setenv("MCP_CONFIG_DIR", tempDir)
	defer func() { _ = os.Unsetenv("MCP_CONFIG_DIR") }()
	
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	
	if !cfg.Notifications.Enabled {
		t.Error("Notifications should be enabled")
	}
	if cfg.Notifications.MinSeverity != "medium" {
		t.Errorf("MinSeverity = %s, want medium", cfg.Notifications.MinSeverity)
	}
	if cfg.Monitoring.IntervalSeconds != 600 {
		t.Errorf("IntervalSeconds = %d, want 600", cfg.Monitoring.IntervalSeconds)
	}
}

// Test Load with invalid YAML
func TestLoadWithInvalidYAML(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ".chihuaudit.yaml")
	
	// Create invalid YAML
	invalidYAML := `
notifications:
  enabled: true
  discord:
    webhookUrl: [invalid yaml structure
`
	if err := os.WriteFile(configPath, []byte(invalidYAML), 0600); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}
	
	_ = os.Setenv("MCP_CONFIG_DIR", tempDir)
	defer func() { _ = os.Unsetenv("MCP_CONFIG_DIR") }()
	
	_, err := Load()
	if err == nil {
		t.Error("Load() should fail with invalid YAML")
	}
}

// Test Validate() with invalid Discord webhook
func TestValidateInvalidDiscordWebhook(t *testing.T) {
	cfg := Default()
	cfg.Notifications.Discord.Enabled = true
	cfg.Notifications.Discord.WebhookURL = "invalid-url-without-protocol"
	
	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() should fail with invalid Discord webhook URL")
	}
	if err != nil && err.Error() != "invalid Discord webhook URL: must start with http:// or https://" {
		t.Errorf("Unexpected error: %v", err)
	}
}

// Test Validate() with invalid Slack webhook
func TestValidateInvalidSlackWebhook(t *testing.T) {
	cfg := Default()
	cfg.Notifications.Slack.Enabled = true
	cfg.Notifications.Slack.WebhookURL = "ftp://invalid-protocol.com"
	
	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() should fail with invalid Slack webhook URL")
	}
}

// Test Validate() with invalid generic webhook
func TestValidateInvalidGenericWebhook(t *testing.T) {
	cfg := Default()
	cfg.Notifications.GenericWebhook.Enabled = true
	cfg.Notifications.GenericWebhook.URL = "not-a-url"
	
	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() should fail with invalid generic webhook URL")
	}
}

// Test Validate() with valid webhooks
func TestValidateValidWebhooks(t *testing.T) {
	cfg := Default()
	cfg.Notifications.Discord.Enabled = true
	cfg.Notifications.Discord.WebhookURL = "https://discord.com/api/webhooks/test"
	cfg.Notifications.Slack.Enabled = true
	cfg.Notifications.Slack.WebhookURL = "https://hooks.slack.com/services/test"
	cfg.Notifications.GenericWebhook.Enabled = true
	cfg.Notifications.GenericWebhook.URL = "http://example.com/webhook"
	
	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() should pass with valid webhooks: %v", err)
	}
}

// Test Validate() with invalid severity
func TestValidateInvalidSeverity(t *testing.T) {
	cfg := Default()
	cfg.Notifications.MinSeverity = "super-critical"
	
	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() should fail with invalid severity")
	}
}

// Test Validate() with valid severities
func TestValidateValidSeverities(t *testing.T) {
	severities := []string{"critical", "high", "medium", "low", "info"}
	
	for _, sev := range severities {
		cfg := Default()
		cfg.Notifications.MinSeverity = sev
		
		err := cfg.Validate()
		if err != nil {
			t.Errorf("Validate() should pass with severity %s: %v", sev, err)
		}
	}
}

// Test Validate() with invalid monitoring interval (too low)
func TestValidateMonitoringIntervalTooLow(t *testing.T) {
	cfg := Default()
	cfg.Monitoring.Enabled = true
	cfg.Monitoring.IntervalSeconds = 5
	
	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() should fail with interval < 10")
	}
}

// Test Validate() with invalid monitoring interval (too high)
func TestValidateMonitoringIntervalTooHigh(t *testing.T) {
	cfg := Default()
	cfg.Monitoring.Enabled = true
	cfg.Monitoring.IntervalSeconds = 90000
	
	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() should fail with interval > 86400")
	}
}

// Test Validate() with valid monitoring interval
func TestValidateMonitoringIntervalValid(t *testing.T) {
	cfg := Default()
	cfg.Monitoring.Enabled = true
	cfg.Monitoring.IntervalSeconds = 3600
	
	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() should pass with valid interval: %v", err)
	}
}

// Test IsAnalyzerEnabled with enabled analyzer
func TestIsAnalyzerEnabledTrue(t *testing.T) {
	cfg := Default()
	cfg.Checks["firewall"] = true
	
	if !cfg.IsAnalyzerEnabled("firewall") {
		t.Error("IsAnalyzerEnabled should return true for enabled analyzer")
	}
}

// Test IsAnalyzerEnabled with disabled analyzer
func TestIsAnalyzerEnabledFalse(t *testing.T) {
	cfg := Default()
	cfg.Checks["firewall"] = false
	
	if cfg.IsAnalyzerEnabled("firewall") {
		t.Error("IsAnalyzerEnabled should return false for disabled analyzer")
	}
}

// Test IsAnalyzerEnabled with non-existent analyzer (should default to true)
func TestIsAnalyzerEnabledNonExistent(t *testing.T) {
	cfg := Default()
	
	if !cfg.IsAnalyzerEnabled("non-existent-analyzer") {
		t.Error("IsAnalyzerEnabled should return true for non-existent analyzer (default)")
	}
}

// Test GetMaxConcurrency with default (0)
func TestGetMaxConcurrencyDefault(t *testing.T) {
	cfg := Default()
	cfg.MaxConcurrency = 0
	
	max := cfg.GetMaxConcurrency()
	if max <= 0 {
		t.Errorf("GetMaxConcurrency() should return positive value, got %d", max)
	}
}

// Test GetMaxConcurrency with custom value
func TestGetMaxConcurrencyCustom(t *testing.T) {
	cfg := Default()
	cfg.MaxConcurrency = 8
	
	max := cfg.GetMaxConcurrency()
	if max != 8 {
		t.Errorf("GetMaxConcurrency() = %d, want 8", max)
	}
}

// Test Load with home directory config
func TestLoadWithHomeConfig(t *testing.T) {
	// This test ensures home directory path is checked
	// Even if no config exists, Load should not fail
	cfg, err := Load()
	if err != nil {
		t.Errorf("Load() should not fail even without config: %v", err)
	}
	if cfg == nil {
		t.Error("Load() should return default config if no file exists")
	}
}

// Test Default config values
func TestDefaultConfigValues(t *testing.T) {
	cfg := Default()
	
	// Check default checks
	if !cfg.Checks["firewall"] {
		t.Error("Default firewall check should be enabled")
	}
	if !cfg.Checks["ssh"] {
		t.Error("Default ssh check should be enabled")
	}
	
	// Check default timeouts
	if cfg.Timeouts.Short != 5 {
		t.Errorf("Default short timeout = %d, want 5", cfg.Timeouts.Short)
	}
	if cfg.Timeouts.Medium != 10 {
		t.Errorf("Default medium timeout = %d, want 10", cfg.Timeouts.Medium)
	}
	if cfg.Timeouts.Long != 30 {
		t.Errorf("Default long timeout = %d, want 30", cfg.Timeouts.Long)
	}
	if cfg.Timeouts.VeryLong != 120 {
		t.Errorf("Default very_long timeout = %d, want 120", cfg.Timeouts.VeryLong)
	}
	
	// Check default monitoring
	if cfg.Monitoring.Enabled {
		t.Error("Default monitoring should be disabled")
	}
	if cfg.Monitoring.IntervalSeconds != 3600 {
		t.Errorf("Default interval = %d, want 3600", cfg.Monitoring.IntervalSeconds)
	}
	
	// Check default notifications
	if cfg.Notifications.Enabled {
		t.Error("Default notifications should be disabled")
	}
	if !cfg.Notifications.OnlyOnIssues {
		t.Error("Default onlyOnIssues should be true")
	}
	if cfg.Notifications.MinSeverity != "high" {
		t.Errorf("Default severity = %s, want high", cfg.Notifications.MinSeverity)
	}
}

// Test Load with discovery patterns merging
func TestLoadWithDiscoveryPatterns(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ".chihuaudit.yaml")
	
	configYAML := `
discovery:
  webServerProcesses:
    - "custom-web"
  databaseProcesses:
    - "custom-db"
  containerProcesses:
    - "custom-runtime"
  riskyPorts:
    9999: "Custom Service"
  webPorts:
    - 8888
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0600); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}
	
	_ = os.Setenv("MCP_CONFIG_DIR", tempDir)
	defer func() { _ = os.Unsetenv("MCP_CONFIG_DIR") }()
	
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	
	// Check that custom patterns are merged
	found := false
	for _, proc := range cfg.Processes.WebServers {
		if proc == "custom-web" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Custom web server process not found in merged patterns")
	}
	
	// Check risky ports
	if service, ok := cfg.Ports.RiskyDatabase[9999]; !ok || service != "Custom Service" {
		t.Error("Custom risky port not found in merged patterns")
	}
}

// Test Load with .yml extension
func TestLoadWithYmlExtension(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ".chihuaudit.yml")
	
	configYAML := `
notifications:
  enabled: true
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0600); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}
	
	_ = os.Setenv("MCP_CONFIG_DIR", tempDir)
	defer func() { _ = os.Unsetenv("MCP_CONFIG_DIR") }()
	
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() should work with .yml extension: %v", err)
	}
	if !cfg.Notifications.Enabled {
		t.Error("Config not loaded from .yml file")
	}
}
