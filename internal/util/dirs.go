package util

import (
	"fmt"
	"os"
)

// GetLogDir returns the appropriate log directory based on user privileges
func GetLogDir() string {
	if os.Geteuid() == 0 {
		return "/var/log/chihuaudit"
	}
	return fmt.Sprintf("/tmp/chihuaudit-%d", os.Getuid())
}

// GetConfigDir returns the appropriate config directory based on user privileges
func GetConfigDir() string {
	if os.Geteuid() == 0 {
		return "/root/.chihuaudit"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".chihuaudit"
	}
	return fmt.Sprintf("%s/.chihuaudit", home)
}
