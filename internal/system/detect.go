package system

import (
	"context"
	"os"
	"runtime"
	"strings"
)

// OSInfo contains information about the operating system
type OSInfo struct {
	System   string `json:"system"`
	Distro   string `json:"distro"`
	Kernel   string `json:"kernel"`
	Hostname string `json:"hostname"`
}

// GetOSInfo returns detailed OS information
func GetOSInfo(ctx context.Context) *OSInfo {
	info := &OSInfo{
		System: runtime.GOOS,
	}

	// Get kernel version
	if result, _ := RunCommand(ctx, TimeoutShort, "uname", "-r"); result != nil && result.Success {
		info.Kernel = strings.TrimSpace(result.Stdout)
	}

	// Get hostname
	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	// Detect distro
	info.Distro = GetDistro(ctx)

	return info
}

// GetDistro detects the Linux distribution
func GetDistro(ctx context.Context) string {
	// Try /etc/os-release
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "ID=") {
				distro := strings.TrimPrefix(line, "ID=")
				distro = strings.Trim(distro, "\"")
				return normalizeDistro(distro)
			}
		}
	}

	// Try lsb_release
	if result, _ := RunCommand(ctx, TimeoutShort, "lsb_release", "-si"); result != nil && result.Success {
		return normalizeDistro(strings.TrimSpace(result.Stdout))
	}

	// Fallback to checking specific files
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return "debian"
	}
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return "rhel"
	}
	if _, err := os.Stat("/etc/arch-release"); err == nil {
		return "arch"
	}

	return "unknown"
}

func normalizeDistro(distro string) string {
	distro = strings.ToLower(distro)
	switch {
	case strings.Contains(distro, "ubuntu"):
		return "ubuntu"
	case strings.Contains(distro, "debian"):
		return "debian"
	case strings.Contains(distro, "centos"):
		return "centos"
	case strings.Contains(distro, "rhel"), strings.Contains(distro, "redhat"):
		return "rhel"
	case strings.Contains(distro, "fedora"):
		return "fedora"
	case strings.Contains(distro, "arch"):
		return "arch"
	case strings.Contains(distro, "alpine"):
		return "alpine"
	default:
		return distro
	}
}

// GetAuthLogPath returns the path to the authentication log
func GetAuthLogPath(ctx context.Context) string {
	distro := GetDistro(ctx)
	switch distro {
	case "ubuntu", "debian":
		return "/var/log/auth.log"
	case "rhel", "centos", "fedora":
		return "/var/log/secure"
	default:
		// Try both and return the one that exists
		if _, err := os.Stat("/var/log/auth.log"); err == nil {
			return "/var/log/auth.log"
		}
		return "/var/log/secure"
	}
}

// IsDebian returns true if the system is Debian-based
func IsDebian(distro string) bool {
	return distro == "debian" || distro == "ubuntu"
}

// IsRHEL returns true if the system is RHEL-based
func IsRHEL(distro string) bool {
	return distro == "rhel" || distro == "centos" || distro == "fedora"
}

// IsServiceEnabled checks if a systemd service is enabled
func IsServiceEnabled(ctx context.Context, serviceName string) bool {
	result, _ := RunCommand(ctx, TimeoutShort, "systemctl", "is-enabled", "--quiet", serviceName)
	return result != nil && result.Success
}
