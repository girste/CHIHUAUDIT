package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsServiceWhitelisted(t *testing.T) {
	wl := &Whitelist{
		Services: []ServiceWhitelist{
			{Port: 22, Bind: "0.0.0.0", Service: "ssh", Reason: "test"},
			{Port: 80, Bind: "127.0.0.1", Service: "http", Reason: "test"},
		},
	}

	tests := []struct {
		port   int
		bind   string
		expect bool
	}{
		{22, "0.0.0.0", true},
		{80, "127.0.0.1", true},
		{22, "127.0.0.1", false},
		{443, "0.0.0.0", false},
	}

	for _, tt := range tests {
		got := wl.IsServiceWhitelisted(tt.port, tt.bind)
		if got != tt.expect {
			t.Errorf("IsServiceWhitelisted(%d, %s) = %v, want %v", tt.port, tt.bind, got, tt.expect)
		}
	}
}

func TestIsWildcardPortAllowed(t *testing.T) {
	wl := &Whitelist{
		Network: NetworkWhitelist{
			AllowedWildcardPorts: []int{22, 80, 443},
		},
	}

	if !wl.IsWildcardPortAllowed(22) {
		t.Error("Port 22 should be allowed")
	}
	if wl.IsWildcardPortAllowed(8080) {
		t.Error("Port 8080 should not be allowed")
	}
}

func TestIsLocalhostPortAllowed(t *testing.T) {
	wl := &Whitelist{
		Network: NetworkWhitelist{
			AllowedLocalhostPorts: []int{3306, 5432},
		},
	}

	if !wl.IsLocalhostPortAllowed(3306) {
		t.Error("Port 3306 should be allowed on localhost")
	}
	if wl.IsLocalhostPortAllowed(22) {
		t.Error("Port 22 should not be allowed on localhost")
	}
}

func TestIsProcessAllowed(t *testing.T) {
	wl := &Whitelist{
		Network: NetworkWhitelist{
			AllowedProcesses: []ProcessWhitelist{
				{Name: "nginx", Bind: "0.0.0.0"},
				{Name: "code*", Bind: "*"},
				{Name: "mysql", Bind: "127.0.0.1"},
			},
		},
	}

	tests := []struct {
		name   string
		bind   string
		expect bool
	}{
		{"nginx", "0.0.0.0", true},
		{"nginx", "127.0.0.1", false},
		{"code-abc123", "0.0.0.0", true},
		{"code", "127.0.0.1", true},
		{"mysql", "127.0.0.1", true},
		{"mysql", "0.0.0.0", false},
		{"unknown", "0.0.0.0", false},
	}

	for _, tt := range tests {
		got := wl.IsProcessAllowed(tt.name, tt.bind)
		if got != tt.expect {
			t.Errorf("IsProcessAllowed(%s, %s) = %v, want %v", tt.name, tt.bind, got, tt.expect)
		}
	}
}

func TestIsCISExcepted(t *testing.T) {
	wl := &Whitelist{
		CIS: CISWhitelist{
			Exceptions: []CISException{
				{ID: "1.1.1", Reason: "test"},
				{ID: "5.2.3", Reason: "test"},
			},
		},
	}

	if !wl.IsCISExcepted("1.1.1") {
		t.Error("CIS 1.1.1 should be excepted")
	}
	if wl.IsCISExcepted("1.1.2") {
		t.Error("CIS 1.1.2 should not be excepted")
	}
}

func TestGetThresholds(t *testing.T) {
	// Test defaults
	wl := &Whitelist{}
	if ram := wl.GetRAMThreshold(); ram != 90.0 {
		t.Errorf("Default RAM threshold = %.1f, want 90.0", ram)
	}
	if swap := wl.GetSwapThreshold(); swap != 10.0 {
		t.Errorf("Default Swap threshold = %.1f, want 10.0", swap)
	}
	if disk := wl.GetDiskThreshold(); disk != 90.0 {
		t.Errorf("Default Disk threshold = %.1f, want 90.0", disk)
	}

	// Test custom values
	wl = &Whitelist{
		Thresholds: ThresholdsConfig{
			Memory: MemoryThresholds{RAMPercent: 85.0, SwapPercent: 15.0},
			Disk:   DiskThresholds{UsagePercent: 80.0},
		},
	}
	if ram := wl.GetRAMThreshold(); ram != 85.0 {
		t.Errorf("Custom RAM threshold = %.1f, want 85.0", ram)
	}
	if swap := wl.GetSwapThreshold(); swap != 15.0 {
		t.Errorf("Custom Swap threshold = %.1f, want 15.0", swap)
	}
	if disk := wl.GetDiskThreshold(); disk != 80.0 {
		t.Errorf("Custom Disk threshold = %.1f, want 80.0", disk)
	}
}

func TestIsAlertWhitelisted(t *testing.T) {
	wl := &Whitelist{
		AlertCodes: []string{"FW-001", "SSH-002", "  sv-003  "},
	}

	tests := []struct {
		code   string
		expect bool
	}{
		{"FW-001", true},
		{"fw-001", true},
		{"SSH-002", true},
		{"SV-003", true},
		{"SV-004", false},
		{"", false},
	}

	for _, tt := range tests {
		got := wl.IsAlertWhitelisted(tt.code)
		if got != tt.expect {
			t.Errorf("IsAlertWhitelisted(%q) = %v, want %v", tt.code, got, tt.expect)
		}
	}

	// Test nil whitelist
	var nilWL *Whitelist
	if nilWL.IsAlertWhitelisted("FW-001") {
		t.Error("Nil whitelist should return false")
	}
}

func TestAddAlertCode(t *testing.T) {
	wl := &Whitelist{}

	wl.AddAlertCode("FW-001")
	if !wl.IsAlertWhitelisted("FW-001") {
		t.Error("Alert code should be added")
	}

	// Test duplicate add
	wl.AddAlertCode("fw-001")
	count := 0
	for _, code := range wl.AlertCodes {
		if code == "FW-001" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Duplicate add should be ignored, got %d occurrences", count)
	}

	// Test nil whitelist
	var nilWL *Whitelist
	nilWL.AddAlertCode("TEST")
}

func TestRemoveAlertCode(t *testing.T) {
	wl := &Whitelist{
		AlertCodes: []string{"FW-001", "SSH-002", "SV-003"},
	}

	removed := wl.RemoveAlertCode("ssh-002")
	if !removed {
		t.Error("RemoveAlertCode should return true when code exists")
	}
	if wl.IsAlertWhitelisted("SSH-002") {
		t.Error("SSH-002 should be removed")
	}

	removed = wl.RemoveAlertCode("NON-EXISTENT")
	if removed {
		t.Error("RemoveAlertCode should return false when code doesn't exist")
	}

	// Test nil whitelist
	var nilWL *Whitelist
	if nilWL.RemoveAlertCode("TEST") {
		t.Error("Nil whitelist should return false")
	}
}

func TestGetWhitelistedAlertCodes(t *testing.T) {
	wl := &Whitelist{
		AlertCodes: []string{"FW-001", "SSH-002"},
	}

	codes := wl.GetWhitelistedAlertCodes()
	if len(codes) != 2 {
		t.Errorf("GetWhitelistedAlertCodes() length = %d, want 2", len(codes))
	}

	var nilWL *Whitelist
	codes = nilWL.GetWhitelistedAlertCodes()
	if len(codes) != 0 {
		t.Errorf("Nil whitelist should return empty slice, got %d codes", len(codes))
	}
}

func TestSaveWhitelist(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "test-whitelist.yaml")

	wl := &Whitelist{
		AlertCodes: []string{"FW-001", "SSH-002"},
		Network: NetworkWhitelist{
			AllowedWildcardPorts: []int{80, 443},
		},
	}

	err := SaveWhitelist(wl, path)
	if err != nil {
		t.Fatalf("SaveWhitelist failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("Whitelist file was not created")
	}

	// Load it back
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read saved whitelist: %v", err)
	}
	if len(data) == 0 {
		t.Error("Saved whitelist is empty")
	}
}

func TestLoadWhitelistWithMCPConfigDir(t *testing.T) {
	tempDir := t.TempDir()
	whitelistPath := filepath.Join(tempDir, ".chihuaudit-whitelist.yaml")

	whitelistYAML := `
alertCodes:
  - "FW-001"
  - "SSH-002"
network:
  allowedWildcardPorts:
    - 80
    - 443
`
	if err := os.WriteFile(whitelistPath, []byte(whitelistYAML), 0600); err != nil {
		t.Fatalf("Failed to create test whitelist: %v", err)
	}

	_ = os.Setenv("MCP_CONFIG_DIR", tempDir)
	defer func() { _ = os.Unsetenv("MCP_CONFIG_DIR") }()

	wl, err := LoadWhitelist()
	if err != nil {
		t.Fatalf("LoadWhitelist failed: %v", err)
	}

	if len(wl.AlertCodes) != 2 {
		t.Errorf("AlertCodes length = %d, want 2", len(wl.AlertCodes))
	}
	if len(wl.Network.AllowedWildcardPorts) != 2 {
		t.Errorf("AllowedWildcardPorts length = %d, want 2", len(wl.Network.AllowedWildcardPorts))
	}
}
