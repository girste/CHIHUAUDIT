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

// IsProcessRunning checks if a process with given name is running on the host
func IsProcessRunning(processName string) bool {
	procPath := HostPath("/proc")
	
	entries, err := os.ReadDir(procPath)
	if err != nil {
		return false
	}
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		// Check if directory name is numeric (PID)
		if entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		
		// Read cmdline to check process name
		cmdlinePath := procPath + "/" + entry.Name() + "/cmdline"
		data, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}
		
		cmdline := string(data)
		if strings.Contains(cmdline, processName) {
			return true
		}
	}
	
	return false
}

// FileExists checks if a file exists on the host
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
