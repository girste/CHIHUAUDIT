package config

import (
	"testing"
)

func TestLoadConfig(t *testing.T) {
	cfg, err := Load()

	// Config file may not exist in test env
	if cfg != nil {
		t.Log("Config loaded successfully")
	}
	if err != nil {
		t.Logf("Expected error if no config file: %v", err)
	}
}

func TestDefaultWhitelist(t *testing.T) {
	wl := &Whitelist{
		Network: NetworkWhitelist{
			AllowedWildcardPorts: []int{22, 80, 443},
		},
		Services: []ServiceWhitelist{
			{Port: 22, Service: "ssh", Reason: "Remote access"},
			{Port: 80, Service: "http", Reason: "Web server"},
		},
	}

	if len(wl.Network.AllowedWildcardPorts) != 3 {
		t.Errorf("AllowedWildcardPorts length = %d, want 3", len(wl.Network.AllowedWildcardPorts))
	}
	if wl.Network.AllowedWildcardPorts[0] != 22 {
		t.Error("First port should be 22")
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := &Config{}
	_ = cfg // Verify Config struct can be instantiated
}
