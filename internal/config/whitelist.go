package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Whitelist contains server-specific exceptions and whitelisted items
type Whitelist struct {
	Version    string             `yaml:"version"`
	Server     ServerInfo         `yaml:"server"`
	Services   []ServiceWhitelist `yaml:"services"`
	Network    NetworkWhitelist   `yaml:"network"`
	AlertCodes []string           `yaml:"alertCodes,omitempty"` // Whitelisted alert codes (FW-001, SSH-003, etc.)
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

// ProcessWhitelist allows whitelisting processes by name regardless of port
type ProcessWhitelist struct {
	Name   string `yaml:"name"`   // Process name (exact match or prefix if ends with *)
	Bind   string `yaml:"bind"`   // "127.0.0.1", "0.0.0.0", or "*" for any bind address
	Reason string `yaml:"reason"` // Why this is whitelisted
}

// NetworkWhitelist contains network-related exceptions
type NetworkWhitelist struct {
	AllowedWildcardPorts  []int              `yaml:"allowedWildcardPorts"`  // Ports allowed on 0.0.0.0
	AllowedLocalhostPorts []int              `yaml:"allowedLocalhostPorts"` // Ports allowed on 127.0.0.1
	AllowedProcesses      []ProcessWhitelist `yaml:"allowedProcesses"`      // Processes allowed regardless of port
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
	Memory       MemoryThresholds  `yaml:"memory,omitempty"`
	Disk         DiskThresholds    `yaml:"disk,omitempty"`
	CPU          CPUThresholds     `yaml:"cpu,omitempty"`
	AnalyzerRisk map[string]string `yaml:"analyzerRisk,omitempty"` // Risk per analyzer: "high", "medium", "low"
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
	searchPaths := []string{}

	// 1. Environment variable (Docker volume)
	if configDir := os.Getenv("MCP_CONFIG_DIR"); configDir != "" {
		searchPaths = append(searchPaths,
			filepath.Join(configDir, ".chihuaudit-whitelist.yaml"),
			filepath.Join(configDir, ".chihuaudit-whitelist.yml"),
		)
	}

	// 2. Current directory
	searchPaths = append(searchPaths,
		".chihuaudit-whitelist.yaml",
		".chihuaudit-whitelist.yml",
	)

	// 3. Home directory
	if home != "" {
		searchPaths = append(searchPaths,
			filepath.Join(home, ".chihuaudit-whitelist.yaml"),
			filepath.Join(home, ".chihuaudit-whitelist.yml"),
		)
	}

	// 4. System-wide
	searchPaths = append(searchPaths, "/etc/chihuaudit/whitelist.yaml")

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
		path = ".chihuaudit-whitelist.yaml"
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

// IsLocalhostPortAllowed checks if a port is allowed on localhost (127.0.0.1)
func (wl *Whitelist) IsLocalhostPortAllowed(port int) bool {
	for _, p := range wl.Network.AllowedLocalhostPorts {
		if p == port {
			return true
		}
	}
	return false
}

// IsProcessAllowed checks if a process is allowed based on name and bind address
func (wl *Whitelist) IsProcessAllowed(processName, bind string) bool {
	for _, proc := range wl.Network.AllowedProcesses {
		// Check process name match (support prefix matching with *)
		nameMatch := false
		if strings.HasSuffix(proc.Name, "*") {
			// Prefix matching: "code*" matches "code", "code-abc123", etc.
			prefix := strings.TrimSuffix(proc.Name, "*")
			nameMatch = strings.HasPrefix(processName, prefix)
		} else {
			// Exact matching
			nameMatch = proc.Name == processName
		}

		if !nameMatch {
			continue
		}

		// Check bind address match (* means any)
		if proc.Bind == "*" || proc.Bind == bind {
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

// GetCPUThreshold returns the 1-min load average threshold (0 = use default: cores×1.5).
func (wl *Whitelist) GetCPUThreshold() float64 {
	if wl.Thresholds.CPU.LoadAvg1Min > 0 {
		return wl.Thresholds.CPU.LoadAvg1Min
	}
	return 0
}

// GetAnalyzerRiskMap returns the configured analyzer→risk mapping.
// Falls back to DefaultAnalyzerRiskMap when no explicit config exists.
func (wl *Whitelist) GetAnalyzerRiskMap() map[string]string {
	if wl != nil && len(wl.Thresholds.AnalyzerRisk) > 0 {
		return wl.Thresholds.AnalyzerRisk
	}
	return DefaultAnalyzerRiskMap()
}

// DefaultAnalyzerRiskMap returns the default risk levels used when the whitelist
// does not specify thresholds.analyzerRisk.  Override in .chihuaudit-whitelist.yaml:
//
//	thresholds:
//	  analyzerRisk:
//	    firewall: high
//	    ssh:      high
//	    ...
func DefaultAnalyzerRiskMap() map[string]string {
	return map[string]string{
		"firewall": "high",
		"ssh":      "high",
		"users":    "high",
		"services": "medium",
		"docker":   "medium",
		"fail2ban": "medium",
		"mac":      "medium",
	}
}

// IsAlertWhitelisted checks if an alert code is whitelisted
func (wl *Whitelist) IsAlertWhitelisted(code string) bool {
if wl == nil {
return false
}

code = strings.TrimSpace(strings.ToUpper(code))

for _, whitelisted := range wl.AlertCodes {
if strings.ToUpper(strings.TrimSpace(whitelisted)) == code {
return true
}
}

return false
}

// AddAlertCode adds an alert code to the whitelist
func (wl *Whitelist) AddAlertCode(code string) {
if wl == nil {
return
}

code = strings.TrimSpace(strings.ToUpper(code))

// Check if already exists
if wl.IsAlertWhitelisted(code) {
return
}

wl.AlertCodes = append(wl.AlertCodes, code)
}

// RemoveAlertCode removes an alert code from the whitelist
func (wl *Whitelist) RemoveAlertCode(code string) bool {
if wl == nil {
return false
}

code = strings.TrimSpace(strings.ToUpper(code))

for i, whitelisted := range wl.AlertCodes {
if strings.ToUpper(strings.TrimSpace(whitelisted)) == code {
// Remove by creating new slice without this element
wl.AlertCodes = append(wl.AlertCodes[:i], wl.AlertCodes[i+1:]...)
return true
}
}

return false
}

// GetWhitelistedAlertCodes returns all whitelisted alert codes
func (wl *Whitelist) GetWhitelistedAlertCodes() []string {
if wl == nil {
return []string{}
}
return wl.AlertCodes
}
