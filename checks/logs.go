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
	// Use journalctl for systemd-based systems (more reliable than log files)
	out, err := exec.Command("journalctl", "--since", "24 hours ago", "-p", "err", "--no-pager").Output()
	if err != nil {
		// Fallback to log files if journalctl fails
		logPath := detect.TryPaths("/var/log/syslog", "/var/log/messages")
		if logPath == "" {
			return 0
		}
		out, err = exec.Command("grep", "-i", "-c", "error", logPath).Output()
		if err != nil {
			return 0
		}
		count, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		return count
	}

	count := 0
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and journalctl headers (starting with --)
		if line != "" && !strings.HasPrefix(line, "-- ") {
			count++
		}
	}

	return count
}

func getSSHFailures() (count int, ips []string) {
	// Use journalctl for systemd-based systems (more accurate, last 24h only)
	out, err := exec.Command("journalctl", "-u", "sshd", "--since", "24 hours ago", "--no-pager").Output()
	if err != nil {
		// Fallback to log files if journalctl fails
		logPath := detect.TryPaths("/var/log/auth.log", "/var/log/secure")
		if logPath == "" {
			return
		}
		out, err = exec.Command("grep", "-c", "Failed password", logPath).Output()
		if err == nil {
			count, _ = strconv.Atoi(strings.TrimSpace(string(out)))
		}
		return
	}

	// Count lines containing "Failed" or "failure" (case insensitive)
	ipMap := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "failed") || strings.Contains(lower, "failure") {
			count++
			
			// Extract IPs if possible
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "from" && i+1 < len(fields) {
					ip := fields[i+1]
					if !ipMap[ip] && len(ips) < 5 {
						ips = append(ips, ip)
						ipMap[ip] = true
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
