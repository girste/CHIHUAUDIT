package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Checks             map[string]bool      `yaml:"checks"`
	ThreatAnalysisDays int                  `yaml:"threatAnalysisDays"`
	AnalyzerTimeout    int                  `yaml:"analyzerTimeoutSeconds"`
	MaxConcurrency     int                  `yaml:"maxConcurrency"`
	MaskData           bool                 `yaml:"maskData"`
	Timeouts           TimeoutConfig        `yaml:"timeouts"`
	Monitoring         MonitoringConfig     `yaml:"monitoring"`
	Notifications      NotifyConfig         `yaml:"notifications"`
	Discovery          DiscoveryConfig      `yaml:"discovery"`      // Service auto-discovery patterns
	Whitelist          *Whitelist           `yaml:"-"`              // Loaded separately
	Ports              *PortPatterns        `yaml:"-"`              // Pattern definitions
	Processes          *ProcessPatterns     `yaml:"-"`              // Process patterns
}

// DiscoveryConfig allows users to customize service auto-discovery patterns
type DiscoveryConfig struct {
	WebServerProcesses   []string       `yaml:"webServerProcesses"`   // Additional web server process names
	DatabaseProcesses    []string       `yaml:"databaseProcesses"`    // Additional database process names
	ContainerProcesses   []string       `yaml:"containerProcesses"`   // Additional container runtime names
	RiskyPorts           map[int]string `yaml:"riskyPorts"`           // Custom risky ports (port: service name)
	WebPorts             []int          `yaml:"webPorts"`             // Additional web ports
	SafeWildcardPorts    []int          `yaml:"safeWildcardPorts"`    // Ports allowed on 0.0.0.0 (bypass warnings)
}

// TimeoutConfig defines configurable timeout durations
type TimeoutConfig struct {
	Short    int `yaml:"short"`     // Short operations (default: 5s)
	Medium   int `yaml:"medium"`    // Medium operations (default: 10s)
	Long     int `yaml:"long"`      // Long operations (default: 30s)
	VeryLong int `yaml:"very_long"` // Very long operations (default: 120s)
}

type MonitoringConfig struct {
	Enabled         bool   `yaml:"enabled"`
	IntervalSeconds int    `yaml:"intervalSeconds"`
	LogDir          string `yaml:"logDir"`
	MaxBulletins    int    `yaml:"maxBulletins"`
	MaxAnomalies    int    `yaml:"maxAnomalies"`
}

// NotifyConfig holds webhook notification settings
type NotifyConfig struct {
	Enabled        bool          `yaml:"enabled"`
	OnlyOnIssues   bool          `yaml:"onlyOnIssues"`
	MinSeverity    string        `yaml:"minSeverity"` // critical, high, medium, low
	Discord        DiscordConfig `yaml:"discord"`
	Slack          SlackConfig   `yaml:"slack"`
	GenericWebhook WebhookConfig `yaml:"webhook"`
}

type DiscordConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhookUrl"`
	Username   string `yaml:"username"`
	AvatarURL  string `yaml:"avatarUrl"`
}

type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhookUrl"`
	Channel    string `yaml:"channel"`
	Username   string `yaml:"username"`
}

type WebhookConfig struct {
	Enabled bool              `yaml:"enabled"`
	URL     string            `yaml:"url"`
	Method  string            `yaml:"method"` // POST, PUT
	Headers map[string]string `yaml:"headers"`
}

func Default() *Config {
	return &Config{
		Checks: map[string]bool{
			"firewall": true, "ssh": true, "threats": true, "fail2ban": true,
			"services": true, "docker": true, "updates": true, "mac": true,
			"kernel": true, "ssl": true, "disk": true, "cve": true,
			"cis": true, "containers": true, "nist": true, "pci": true,
			"filesystem": true, "network": true, "users": true, "rootkit": true,
			"sudoers": true, "system": true, "webheaders": true,
			"app_security": true, "net_security": true, "db_security": true,
			"backup": true, "vuln_intel": true,
		},
		ThreatAnalysisDays: 7,
		AnalyzerTimeout:    10,
		MaxConcurrency:     0,
		MaskData:           true,
		Timeouts: TimeoutConfig{
			Short:    5,
			Medium:   10,
			Long:     30,
			VeryLong: 120,
		},
		Monitoring: MonitoringConfig{
			Enabled: false, IntervalSeconds: 3600,
			LogDir: "/var/log/chihuaudit", MaxBulletins: 50, MaxAnomalies: 20,
		},
		Notifications: NotifyConfig{
			Enabled:      false,
			OnlyOnIssues: true,
			MinSeverity:  "high",
			Discord: DiscordConfig{
				Username:  "Chihuaudit",
				AvatarURL: "",
			},
			Slack: SlackConfig{
				Username: "Chihuaudit",
			},
			GenericWebhook: WebhookConfig{
				Method: "POST",
			},
		},
	}
}

func Load() (*Config, error) {
	cfg := Default()
	home, _ := os.UserHomeDir()

	// Build search paths with priority order
	searchPaths := []string{}

	// 1. Environment variable (highest priority - for Docker)
	if configDir := os.Getenv("MCP_CONFIG_DIR"); configDir != "" {
		searchPaths = append(searchPaths,
			filepath.Join(configDir, ".chihuaudit.yaml"),
			filepath.Join(configDir, ".chihuaudit.yml"),
		)
	}

	// 2. Current directory
	searchPaths = append(searchPaths,
		".chihuaudit.yaml", ".chihuaudit.yml",
	)

	// 3. Home directory
	if home != "" {
		searchPaths = append(searchPaths,
			filepath.Join(home, ".chihuaudit.yaml"),
			filepath.Join(home, ".chihuaudit.yml"),
		)
	}

	// 4. System-wide config
	searchPaths = append(searchPaths, "/etc/chihuaudit/config.yaml")
	// Try each path in priority order
	configLoaded := false
	for _, path := range searchPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("invalid config at %s: %w", path, err)
		}
		configLoaded = true
		break
	}

	// Validate config if loaded
	if configLoaded {
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("config validation failed: %w", err)
		}
	}

	// Load whitelist separately
	wl, err := LoadWhitelist()
	if err != nil {
		return nil, err
	}
	cfg.Whitelist = wl

	// Load default patterns
	cfg.Ports = DefaultPortPatterns()
	cfg.Processes = DefaultProcessPatterns()
	
	// Merge user-defined discovery patterns with defaults
	if cfg.Discovery.WebServerProcesses != nil {
		cfg.Processes.WebServers = append(cfg.Processes.WebServers, cfg.Discovery.WebServerProcesses...)
	}
	if cfg.Discovery.DatabaseProcesses != nil {
		cfg.Processes.Databases = append(cfg.Processes.Databases, cfg.Discovery.DatabaseProcesses...)
	}
	if cfg.Discovery.ContainerProcesses != nil {
		cfg.Processes.ContainerRuntime = append(cfg.Processes.ContainerRuntime, cfg.Discovery.ContainerProcesses...)
	}
	if cfg.Discovery.RiskyPorts != nil {
		for port, service := range cfg.Discovery.RiskyPorts {
			cfg.Ports.RiskyDatabase[port] = service
		}
	}
	if cfg.Discovery.WebPorts != nil {
		cfg.Ports.WebPorts = append(cfg.Ports.WebPorts, cfg.Discovery.WebPorts...)
	}

	return cfg, nil
}

func (c *Config) IsAnalyzerEnabled(name string) bool {
	enabled, ok := c.Checks[name]
	return !ok || enabled
}

func (c *Config) GetMaxConcurrency() int {
	if c.MaxConcurrency <= 0 {
		return runtime.NumCPU() * 2
	}
	return c.MaxConcurrency
}

// Validate checks config for errors
func (c *Config) Validate() error {
	// Validate Discord webhook
	if c.Notifications.Discord.Enabled && c.Notifications.Discord.WebhookURL != "" {
		url := strings.TrimSpace(c.Notifications.Discord.WebhookURL)
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return fmt.Errorf("invalid Discord webhook URL: must start with http:// or https://")
		}
	}

	// Validate Slack webhook
	if c.Notifications.Slack.Enabled && c.Notifications.Slack.WebhookURL != "" {
		url := strings.TrimSpace(c.Notifications.Slack.WebhookURL)
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return fmt.Errorf("invalid Slack webhook URL: must start with http:// or https://")
		}
	}

	// Validate generic webhook
	if c.Notifications.GenericWebhook.Enabled && c.Notifications.GenericWebhook.URL != "" {
		url := strings.TrimSpace(c.Notifications.GenericWebhook.URL)
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return fmt.Errorf("invalid generic webhook URL: must start with http:// or https://")
		}
	}

	// Validate severity
	validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	if !validSeverities[c.Notifications.MinSeverity] {
		return fmt.Errorf("invalid min_severity: %s (must be: critical, high, medium, low, info)", c.Notifications.MinSeverity)
	}

	// Validate monitoring interval
	if c.Monitoring.Enabled && (c.Monitoring.IntervalSeconds < 10 || c.Monitoring.IntervalSeconds > 86400) {
		return fmt.Errorf("monitoring interval must be between 10 and 86400 seconds, got: %d", c.Monitoring.IntervalSeconds)
	}

	return nil
}
