package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	CloudURL            string              `json:"cloud_url,omitempty"`
	APIKey              string              `json:"api_key,omitempty"`
	DiscordWebhook      string              `json:"discord_webhook"`
	NotificationFilters NotificationFilters `json:"notification_whitelist"`
}

type NotificationFilters struct {
	CPUThreshold    float64  `json:"cpu_threshold"`
	MemoryThreshold float64  `json:"memory_threshold"`
	DiskThreshold   float64  `json:"disk_threshold"`
	IgnoreChanges   []string `json:"ignore_changes"`
}

// Defaults
var DefaultFilters = NotificationFilters{
	CPUThreshold:    60.0,
	MemoryThreshold: 60.0,
	DiskThreshold:   80.0,
	IgnoreChanges: []string{
		"uptime",
		"active_connections",
		"process_list",
		"network_rx_tx",
	},
}

func Load() *Config {
	cfg := &Config{
		NotificationFilters: DefaultFilters,
	}

	// Try config locations in order
	paths := []string{
		filepath.Join(os.Getenv("HOME"), ".chihuaudit", "config.json"),
		"/etc/chihuaudit/config.json",
	}

	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(data, cfg); err == nil {
				return cfg
			}
		}
	}

	return cfg
}

func (c *Config) ShouldIgnore(changeKey string) bool {
	for _, ignored := range c.NotificationFilters.IgnoreChanges {
		if ignored == changeKey {
			return true
		}
	}
	return false
}
