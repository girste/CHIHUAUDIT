package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzConfigParsing tests config YAML unmarshaling with random input
func FuzzConfigParsing(f *testing.F) {
	// Seed corpus with valid examples
	f.Add([]byte(`notifications:
  enabled: true
  discord:
    webhookUrl: "https://discord.com/api/webhooks/test"
    username: "Test Bot"
monitoring:
  intervalSeconds: 300
  logDir: /var/log/test
`))

	f.Add([]byte(`checks:
  firewall: true
  ssh: false
threatAnalysisDays: 7
analyzerTimeoutSeconds: 10
maxConcurrency: 4
maskData: true
`))

	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`invalid: [[[`))

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := Default()
		// Should not panic on any YAML input
		_ = yaml.Unmarshal(data, cfg)
	})
}

// FuzzWhitelistParsing tests whitelist YAML unmarshaling
func FuzzWhitelistParsing(f *testing.F) {
	f.Add([]byte(`version: "1.0"
services:
  - port: 5432
    bind: "127.0.0.1"
    service: "PostgreSQL"
    reason: "Internal database"
network:
  allowedWildcardPorts: [80, 443, 8080]
cis:
  exceptions:
    - id: "3.2.2"
      reason: "Docker requires IP forwarding"
thresholds:
  memory:
    ram_percent: 95.0
    swap_percent: 30.0
`))

	f.Add([]byte(`version: "1.0"`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`[[[invalid yaml`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var wl Whitelist
		// Should not panic on malformed whitelist YAML
		_ = yaml.Unmarshal(data, &wl)
	})
}

// FuzzNotifyConfigParsing tests notification config parsing
func FuzzNotifyConfigParsing(f *testing.F) {
	f.Add([]byte(`enabled: true
onlyOnIssues: false
minSeverity: "high"
discord:
  enabled: true
  webhookUrl: "https://discord.com/api/test"
  username: "Bot"
slack:
  enabled: false
webhook:
  enabled: false
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var nc NotifyConfig
		// Should not panic on notification config
		_ = yaml.Unmarshal(data, &nc)
	})
}
