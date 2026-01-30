package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Whitelist contains server-specific exceptions and whitelisted items
type Whitelist struct {
	Version    string             `yaml:"version"`
	Server     ServerInfo         `yaml:"server"`
	Services   []ServiceWhitelist `yaml:"services"`
	Network    NetworkWhitelist   `yaml:"network"`
	CIS        CISWhitelist       `yaml:"cis"`
	Thresholds ThresholdsConfig   `yaml:"thresholds,omitempty"`
}

// ServerInfo contains optional metadata about the server
type ServerInfo struct {
	Role        string `yaml:"role"`        // e.g., "web", "db", "docker-host"
	Environment string `yaml:"environment"` // e.g., "production", "development"
	Notes       string `yaml:"notes"`
}

// ServiceWhitelist allows whitelisting specific services/ports
type ServiceWhitelist struct {
	Port    int    `yaml:"port"`
	Bind    string `yaml:"bind"`    // e.g., "127.0.0.1", "0.0.0.0"
	Service string `yaml:"service"` // e.g., "PostgreSQL", "Redis"
	Reason  string `yaml:"reason"`  // Why this is whitelisted
}

// NetworkWhitelist contains network-related exceptions
type NetworkWhitelist struct {
	AllowedWildcardPorts []int `yaml:"allowedWildcardPorts"` // Ports allowed on 0.0.0.0
}

// CISWhitelist contains CIS benchmark exceptions
type CISWhitelist struct {
	Exceptions []CISException `yaml:"exceptions"`
}

// CISException represents an exception for a specific CIS control
type CISException struct {
	ID     string `yaml:"id"`     // e.g., "3.2.2"
	Reason string `yaml:"reason"` // Why this control is excepted
}

// ThresholdsConfig contains customizable alert thresholds
type ThresholdsConfig struct {
	Memory MemoryThresholds `yaml:"memory,omitempty"`
	Disk   DiskThresholds   `yaml:"disk,omitempty"`
	CPU    CPUThresholds    `yaml:"cpu,omitempty"`
}

// MemoryThresholds for RAM and swap alerts
type MemoryThresholds struct {
	RAMPercent  float64 `yaml:"ram_percent,omitempty"`  // Default: 90.0
	SwapPercent float64 `yaml:"swap_percent,omitempty"` // Default: 10.0
}

// DiskThresholds for disk usage alerts
type DiskThresholds struct {
	UsagePercent float64 `yaml:"usage_percent,omitempty"` // Default: 90.0
}

// CPUThresholds for CPU load alerts
type CPUThresholds struct {
	LoadAvg1Min  float64 `yaml:"load_avg_1min,omitempty"`  // Default: cores * 2
	LoadAvg5Min  float64 `yaml:"load_avg_5min,omitempty"`  // Default: cores * 1.5
	LoadAvg15Min float64 `yaml:"load_avg_15min,omitempty"` // Default: cores * 1
}

// LoadWhitelist loads the whitelist from standard locations
func LoadWhitelist() (*Whitelist, error) {
	wl := &Whitelist{Version: "1.0"}

	home, _ := os.UserHomeDir()
	searchPaths := []string{
		".mcp-watchdog-whitelist.yaml",
		".mcp-watchdog-whitelist.yml",
		filepath.Join(home, ".mcp-watchdog-whitelist.yaml"),
		filepath.Join(home, ".mcp-watchdog-whitelist.yml"),
		"/etc/mcp-watchdog/whitelist.yaml",
	}

	for _, path := range searchPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := yaml.Unmarshal(data, wl); err != nil {
			return nil, err
		}
		return wl, nil
	}

	// No whitelist file found - return empty whitelist
	return wl, nil
}

// SaveWhitelist saves the whitelist to the local directory
func SaveWhitelist(wl *Whitelist, path string) error {
	if path == "" {
		path = ".mcp-watchdog-whitelist.yaml"
	}

	data, err := yaml.Marshal(wl)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// IsServiceWhitelisted checks if a service/port/bind combination is whitelisted
func (wl *Whitelist) IsServiceWhitelisted(port int, bind string) bool {
	for _, svc := range wl.Services {
		if svc.Port == port && svc.Bind == bind {
			return true
		}
	}
	return false
}

// IsWildcardPortAllowed checks if a port is allowed on wildcard (0.0.0.0)
func (wl *Whitelist) IsWildcardPortAllowed(port int) bool {
	for _, p := range wl.Network.AllowedWildcardPorts {
		if p == port {
			return true
		}
	}
	return false
}

// IsCISExcepted checks if a CIS control is excepted
func (wl *Whitelist) IsCISExcepted(controlID string) bool {
	for _, exc := range wl.CIS.Exceptions {
		if exc.ID == controlID {
			return true
		}
	}
	return false
}

// GetRAMThreshold returns the RAM threshold with default fallback
func (wl *Whitelist) GetRAMThreshold() float64 {
	if wl.Thresholds.Memory.RAMPercent > 0 {
		return wl.Thresholds.Memory.RAMPercent
	}
	return 90.0 // Default: 90%
}

// GetSwapThreshold returns the Swap threshold with default fallback
func (wl *Whitelist) GetSwapThreshold() float64 {
	if wl.Thresholds.Memory.SwapPercent > 0 {
		return wl.Thresholds.Memory.SwapPercent
	}
	return 10.0 // Default: 10%
}

// GetDiskThreshold returns the disk usage threshold with default fallback
func (wl *Whitelist) GetDiskThreshold() float64 {
	if wl.Thresholds.Disk.UsagePercent > 0 {
		return wl.Thresholds.Disk.UsagePercent
	}
	return 90.0 // Default: 90%
}
