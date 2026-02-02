// Package system provides container-aware system utilities.
// When running in Docker with host mounts, paths are automatically
// prefixed with /host to access the host filesystem.
package system

import (
	"os"
	"strings"
)

// hostRoot is set to "/host" when running in container with host mounts
var hostRoot = ""

// init detects if running in container and sets host root prefix
func init() {
	// Check if running in container with host mounts
	if _, err := os.Stat("/host/proc"); err == nil {
		hostRoot = "/host"
	}
}

// HostPath returns path with /host prefix if in container
func HostPath(path string) string {
	if hostRoot == "" {
		return path
	}

	// Don't double-prefix
	if strings.HasPrefix(path, "/host/") {
		return path
	}

	return hostRoot + path
}

// IsInContainer returns true if running in containerized environment
func IsInContainer() bool {
	return hostRoot != ""
}
