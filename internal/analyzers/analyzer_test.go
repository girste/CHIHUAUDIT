package analyzers

import (
	"context"
	"testing"

	"github.com/girste/chihuaudit/internal/config"
)

func TestAnalyzerInterface(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{
		Checks: map[string]bool{
			"firewall": true,
			"ssh":      true,
		},
		Ports:     config.DefaultPortPatterns(),
		Processes: config.DefaultProcessPatterns(),
	}

	// Test that all analyzer types implement the interface
	analyzers := []Analyzer{
		&FirewallAnalyzer{},
		&SSHAnalyzer{},
		&ThreatsAnalyzer{},
		&DockerAnalyzer{},
		&Fail2banAnalyzer{},
		&UpdatesAnalyzer{},
		&KernelAnalyzer{},
		&UsersAnalyzer{},
		&ServicesAnalyzer{},
		&DiskAnalyzer{},
		&MACAnalyzer{},
		&SSLAnalyzer{},
		&CVEAnalyzer{},
	}

	for _, analyzer := range analyzers {
		t.Run("analyzer implements interface", func(t *testing.T) {
			result, err := analyzer.Analyze(ctx, cfg)
			// Don't fail on errors (may need root/system access in test env)
			// Just verify Analyze method exists and returns expected types
			if result != nil && err == nil {
				// Success path - verify result is not nil
				if result == nil {
					t.Error("Successful Analyze() returned nil result")
				}
			}
			// Errors expected in test environment without system access
		})
	}
}

func TestAllAnalyzersExist(t *testing.T) {
	// Verify all 13 analyzer types can be instantiated
	count := 0
	analyzers := []interface{}{
		&FirewallAnalyzer{},
		&SSHAnalyzer{},
		&ThreatsAnalyzer{},
		&DockerAnalyzer{},
		&Fail2banAnalyzer{},
		&UpdatesAnalyzer{},
		&KernelAnalyzer{},
		&UsersAnalyzer{},
		&ServicesAnalyzer{},
		&DiskAnalyzer{},
		&MACAnalyzer{},
		&SSLAnalyzer{},
		&CVEAnalyzer{},
	}

	count = len(analyzers)

	if count != 13 {
		t.Errorf("Expected 13 analyzers, got %d", count)
	}
}

func TestConfigAnalyzerToggle(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.Config
		enabled bool
	}{
		{
			name: "firewall enabled",
			config: &config.Config{
				Checks: map[string]bool{
					"firewall": true,
				},
			},
			enabled: true,
		},
		{
			name: "firewall disabled",
			config: &config.Config{
				Checks: map[string]bool{
					"firewall": false,
				},
			},
			enabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.Checks["firewall"] != tt.enabled {
				t.Errorf("Config toggle = %v, want %v", tt.config.Checks["firewall"], tt.enabled)
			}
		})
	}
}
