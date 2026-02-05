package detect

import (
	"os"
	"os/exec"
)

// CommandExists checks if a command is available in PATH
func CommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TryPaths returns the first existing path from the list
func TryPaths(paths ...string) string {
	for _, p := range paths {
		if FileExists(p) {
			return p
		}
	}
	return ""
}

// DetectFirewall returns the available firewall tool
func DetectFirewall() string {
	if CommandExists("ufw") {
		return "ufw"
	}
	if CommandExists("firewall-cmd") {
		return "firewalld"
	}
	if CommandExists("iptables") {
		return "iptables"
	}
	return ""
}

// DetectPackageManager returns the available package manager
func DetectPackageManager() string {
	if CommandExists("apt") || CommandExists("apt-get") {
		return "apt"
	}
	if CommandExists("dnf") {
		return "dnf"
	}
	if CommandExists("yum") {
		return "yum"
	}
	if CommandExists("pacman") {
		return "pacman"
	}
	if CommandExists("apk") {
		return "apk"
	}
	return ""
}

// DetectInitSystem returns the init system
func DetectInitSystem() string {
	if CommandExists("systemctl") {
		return "systemd"
	}
	if FileExists("/etc/init.d") {
		return "sysvinit"
	}
	return "unknown"
}
