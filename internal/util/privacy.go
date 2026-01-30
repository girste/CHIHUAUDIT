package util

import (
	"os"
	"strings"
)

// MaskIP masks an IP address for privacy
func MaskIP(ip string) string {
	if ip == "" {
		return "***"
	}

	// IPv6
	if strings.Contains(ip, ":") {
		parts := strings.Split(ip, ":")
		if len(parts) > 0 {
			return parts[0] + ":***"
		}
		return "***"
	}

	// IPv4
	parts := strings.Split(ip, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1] + ".***." + "***"
	}

	return "***"
}

// MaskHostname masks a hostname for privacy
func MaskHostname(hostname string) string {
	if len(hostname) == 0 {
		return "srv-****"
	}
	if len(hostname) == 1 {
		return "srv-" + hostname + "***"
	}
	if len(hostname) < 4 {
		return "srv-" + hostname[:2] + "**"
	}
	return "srv-" + hostname[:2] + "**"
}

// GetMaskedHostname returns the current hostname masked
func GetMaskedHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "srv-****"
	}
	return MaskHostname(hostname)
}
