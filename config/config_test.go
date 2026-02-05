package config

import (
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg := Load()
	if cfg == nil {
		t.Fatal("Load() returned nil")
	}
	if cfg.NotificationFilters.CPUThreshold != 60.0 {
		t.Errorf("Expected CPU threshold 60.0, got %f", cfg.NotificationFilters.CPUThreshold)
	}
}
