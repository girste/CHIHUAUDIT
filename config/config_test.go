package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_WithValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".chihuaudit")
	_ = os.MkdirAll(configDir, 0755)
	
	configPath := filepath.Join(configDir, "config.json")
	testConfig := Config{
		DiscordWebhook: "https://discord.com/webhook/test",
		NotificationFilters: NotificationFilters{
			CPUThreshold:    70.0,
			MemoryThreshold: 75.0,
			DiskThreshold:   85.0,
			IgnoreChanges:   []string{"test_change"},
		},
	}
	
	data, _ := json.Marshal(testConfig)
	_ = os.WriteFile(configPath, data, 0644)
	
	// Temporarily set HOME
	oldHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)
	
	cfg := Load()
	
	if cfg.DiscordWebhook != testConfig.DiscordWebhook {
		t.Errorf("DiscordWebhook = %q, want %q", cfg.DiscordWebhook, testConfig.DiscordWebhook)
	}
	if cfg.NotificationFilters.CPUThreshold != 70.0 {
		t.Errorf("CPUThreshold = %v, want 70.0", cfg.NotificationFilters.CPUThreshold)
	}
}

func TestLoad_WithoutConfig(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)
	
	cfg := Load()
	
	// Should return default config
	if cfg.NotificationFilters.CPUThreshold != DefaultFilters.CPUThreshold {
		t.Errorf("CPUThreshold = %v, want %v", cfg.NotificationFilters.CPUThreshold, DefaultFilters.CPUThreshold)
	}
	if cfg.NotificationFilters.DiskThreshold != DefaultFilters.DiskThreshold {
		t.Errorf("DiskThreshold = %v, want %v", cfg.NotificationFilters.DiskThreshold, DefaultFilters.DiskThreshold)
	}
}

func TestShouldIgnore(t *testing.T) {
	cfg := &Config{
		NotificationFilters: NotificationFilters{
			IgnoreChanges: []string{"uptime", "connections"},
		},
	}
	
	tests := []struct {
		name      string
		changeKey string
		want      bool
	}{
		{"ignored change", "uptime", true},
		{"another ignored", "connections", true},
		{"not ignored", "cpu_usage", false},
		{"empty key", "", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cfg.ShouldIgnore(tt.changeKey)
			if got != tt.want {
				t.Errorf("ShouldIgnore(%q) = %v, want %v", tt.changeKey, got, tt.want)
			}
		})
	}
}

func TestDefaultFilters(t *testing.T) {
	if DefaultFilters.CPUThreshold != 60.0 {
		t.Errorf("DefaultFilters.CPUThreshold = %v, want 60.0", DefaultFilters.CPUThreshold)
	}
	if DefaultFilters.MemoryThreshold != 60.0 {
		t.Errorf("DefaultFilters.MemoryThreshold = %v, want 60.0", DefaultFilters.MemoryThreshold)
	}
	if DefaultFilters.DiskThreshold != 80.0 {
		t.Errorf("DefaultFilters.DiskThreshold = %v, want 80.0", DefaultFilters.DiskThreshold)
	}
	if len(DefaultFilters.IgnoreChanges) == 0 {
		t.Error("DefaultFilters.IgnoreChanges should not be empty")
	}
}
