package checks

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"chihuaudit/detect"
)

func CheckSystemTuning() SystemTuning {
	t := SystemTuning{}

	t.NTPStatus, t.NTPService = checkNTPSyncStatus()
	t.FileDescriptorsCurrent, t.FileDescriptorsMax = checkFileDescriptors()
	t.SysctlParams = getSysctlParams()

	return t
}

func checkNTPSyncStatus() (status, service string) {
	if !detect.CommandExists("timedatectl") {
		return "unknown", "not available"
	}

	out, err := exec.Command("timedatectl", "status").Output()
	if err != nil {
		return "unknown", "error"
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "System clock synchronized:") {
			if strings.Contains(line, "yes") {
				status = "synchronized"
			} else {
				status = "not synchronized"
			}
		}
		if strings.Contains(line, "NTP service:") {
			if strings.Contains(line, "active") {
				service = "active"
			} else {
				service = "inactive"
			}
		}
	}

	if status == "" {
		status = "unknown"
	}
	if service == "" {
		service = "unknown"
	}

	return
}

func checkFileDescriptors() (current, max int) {
	// Current open file descriptors
	data, err := os.ReadFile("/proc/sys/fs/file-nr")
	if err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			current, _ = strconv.Atoi(fields[0])
		}
	}

	// Maximum file descriptors
	data, err = os.ReadFile("/proc/sys/fs/file-max")
	if err == nil {
		max, _ = strconv.Atoi(strings.TrimSpace(string(data)))
	}

	return
}

func getSysctlParams() map[string]string {
	params := make(map[string]string)

	keys := []string{
		"net.core.somaxconn",
		"net.ipv4.tcp_max_syn_backlog",
		"net.ipv4.ip_local_port_range",
		"vm.swappiness",
	}

	for _, key := range keys {
		out, err := exec.Command("sysctl", "-n", key).Output()
		if err == nil {
			params[key] = strings.TrimSpace(string(out))
		}
	}

	return params
}
