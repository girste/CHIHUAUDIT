package config

import (
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Checks             map[string]bool  `yaml:"checks"`
	ThreatAnalysisDays int              `yaml:"threatAnalysisDays"`
	AnalyzerTimeout    int              `yaml:"analyzerTimeoutSeconds"`
	MaxConcurrency     int              `yaml:"maxConcurrency"`
	MaskData           bool             `yaml:"maskData"`
	Monitoring         MonitoringConfig `yaml:"monitoring"`
}

type MonitoringConfig struct {
	Enabled         bool   `yaml:"enabled"`
	IntervalSeconds int    `yaml:"intervalSeconds"`
	LogDir          string `yaml:"logDir"`
	MaxBulletins    int    `yaml:"maxBulletins"`
	MaxAnomalies    int    `yaml:"maxAnomalies"`
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
		Monitoring: MonitoringConfig{
			Enabled: false, IntervalSeconds: 3600,
			LogDir: "/var/log/mcp-watchdog", MaxBulletins: 50, MaxAnomalies: 20,
		},
	}
}

func Load() (*Config, error) {
	cfg := Default()
	home, _ := os.UserHomeDir()
	searchPaths := []string{
		".mcp-watchdog.yaml", ".mcp-watchdog.yml",
		filepath.Join(home, ".mcp-watchdog.yaml"),
		filepath.Join(home, ".mcp-watchdog.yml"),
		"/etc/mcp-watchdog/config.yaml",
	}
	for _, path := range searchPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
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
