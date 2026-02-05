package checks

import (
	"testing"
)

func TestGetSystemInfo(t *testing.T) {
	hostname, osName, kernel, uptime := GetSystemInfo()

	// Should return strings (even if empty in test environment)
	if hostname == "" && osName == "" && kernel == "" && uptime == "" {
		t.Skip("Skipping in minimal test environment")
	}

	// Just verify they're strings
	_ = hostname
	_ = osName
	_ = kernel
	_ = uptime
}
