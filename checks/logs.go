package checks

import (
	"os/exec"
	"strconv"
	"strings"

	"chihuaudit/detect"
)

func CheckLogs() Logs {
	l := Logs{}

	l.SyslogErrors = countSyslogErrors()
	l.SSHFailed, l.SSHFailedIPs = getSSHFailures()
	l.ServiceRestarts = getServiceRestarts()

	return l
}

func countSyslogErrors() int {
	logPath := detect.TryPaths("/var/log/syslog", "/var/log/messages")
	if logPath == "" {
		return 0
	}

	out, err := exec.Command("grep", "-i", "-c", "error", logPath).Output()
	if err != nil {
		return 0
	}

	count, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return count
}

func getSSHFailures() (count int, ips []string) {
	logPath := detect.TryPaths("/var/log/auth.log", "/var/log/secure")
	if logPath == "" {
		return
	}

	// Count failed attempts
	out, err := exec.Command("grep", "-c", "Failed password", logPath).Output()
	if err == nil {
		count, _ = strconv.Atoi(strings.TrimSpace(string(out)))
	}

	// Get unique IPs
	out, err = exec.Command("grep", "Failed password", logPath).Output()
	if err != nil {
		return
	}

	ipMap := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i, field := range fields {
			if field == "from" && i+1 < len(fields) {
				ip := fields[i+1]
				if !ipMap[ip] {
					ips = append(ips, ip)
					ipMap[ip] = true
					if len(ips) >= 5 { // Limit to top 5
						return
					}
				}
			}
		}
	}

	return
}

func getServiceRestarts() []ServiceRestart {
	var restarts []ServiceRestart

	if !detect.CommandExists("journalctl") {
		return restarts
	}

	// Get service restart events from last 7 days
	out, err := exec.Command("journalctl", "-u", "*.service", "--since", "7 days ago", "-o", "short-iso").Output()
	if err != nil {
		return restarts
	}

	serviceCount := make(map[string]int)

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Started") || strings.Contains(line, "Restarted") {
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.HasSuffix(field, ".service") {
					service := strings.TrimSuffix(field, ".service")
					serviceCount[service]++
				}
			}
		}
	}

	// Convert to slice
	for service, count := range serviceCount {
		if count > 0 {
			restarts = append(restarts, ServiceRestart{
				Service:  service,
				Count:    count,
				LastTime: "within 7 days",
			})
		}
	}

	return restarts
}
