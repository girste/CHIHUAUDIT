package checks

import (
	"os"
	"strings"
)

// GetSystemInfo returns basic system information
func GetSystemInfo() (hostname, osName, kernel, uptime string) {
	// Hostname from /etc/hostname or /proc/sys/kernel/hostname
	if data, err := os.ReadFile("/etc/hostname"); err == nil {
		hostname = strings.TrimSpace(string(data))
	}
	
	// OS info from /etc/os-release
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	
	// Kernel version
	if data, err := os.ReadFile("/proc/version"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) >= 3 {
			kernel = parts[2]
		}
	}
	
	// Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			uptime = fields[0] + "s" // Will format properly later
		}
	}
	
	return
}
