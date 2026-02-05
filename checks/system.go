package checks

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"chihuaudit/detect"
)

func CheckSystem() System {
	s := System{}

	s.ListeningPorts = countListeningPorts()
	s.ActiveConns = countActiveConnections()
	s.CronJobs = countCronJobs()
	s.SystemdTimers = countSystemdTimers()
	s.LastReboot = getLastReboot()
	s.PendingUpdates, s.SecurityUpdates = getPendingUpdates()
	s.NTPSync, s.NTPOffset = checkNTPSync()

	return s
}

func countListeningPorts() int {
	var out []byte
	var err error

	if detect.CommandExists("ss") {
		out, err = exec.Command("ss", "-tuln").Output()
	} else if detect.CommandExists("netstat") {
		out, err = exec.Command("netstat", "-tuln").Output()
	}

	if err != nil {
		return 0
	}

	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "LISTEN") {
			count++
		}
	}

	return count
}

func countActiveConnections() int {
	var out []byte
	var err error

	if detect.CommandExists("ss") {
		out, err = exec.Command("ss", "-tun").Output()
	} else if detect.CommandExists("netstat") {
		out, err = exec.Command("netstat", "-tun").Output()
	}

	if err != nil {
		return 0
	}

	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "ESTABLISHED") {
			count++
		}
	}

	return count
}

func countCronJobs() int {
	count := 0

	// Root crontab
	out, err := exec.Command("crontab", "-l").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				count++
			}
		}
	}

	// System cron directories
	cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"}
	for _, dir := range cronDirs {
		if entries, err := os.ReadDir(dir); err == nil {
			count += len(entries)
		}
	}

	return count
}

func countSystemdTimers() int {
	if !detect.CommandExists("systemctl") {
		return 0
	}

	out, err := exec.Command("systemctl", "list-timers", "--no-pager", "--no-legend", "--all").Output()
	if err != nil {
		return 0
	}

	result := strings.TrimSpace(string(out))
	if result == "" {
		return 0
	}

	return len(strings.Split(result, "\n"))
}

func getLastReboot() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "unknown"
	}

	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "unknown"
	}

	uptimeSec, _ := strconv.ParseFloat(fields[0], 64)
	days := int(uptimeSec / 86400)

	if days == 0 {
		return "today"
	}

	return strconv.Itoa(days) + " days ago"
}

func getPendingUpdates() (total, security int) {
	pm := detect.DetectPackageManager()

	switch pm {
	case "apt":
		// Update package list
		_ = exec.Command("apt-get", "update", "-qq").Run()

		out, err := exec.Command("apt", "list", "--upgradable").Output()
		if err != nil {
			return
		}

		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 1 {
			total = len(lines) - 1 // Exclude header
		}

		// Count security updates
		out, err = exec.Command("apt", "list", "--upgradable").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "security") {
					security++
				}
			}
		}

	case "yum", "dnf":
		cmd := "yum"
		if pm == "dnf" {
			cmd = "dnf"
		}

		out, err := exec.Command(cmd, "check-update", "-q").Output()
		if err == nil {
			result := strings.TrimSpace(string(out))
			if result != "" {
				total = len(strings.Split(result, "\n"))
			}
		}

		// Security updates
		out, err = exec.Command(cmd, "updateinfo", "list", "security", "-q").Output()
		if err == nil {
			result := strings.TrimSpace(string(out))
			if result != "" {
				security = len(strings.Split(result, "\n"))
			}
		}
	}

	return
}

func checkNTPSync() (synced bool, offset string) {
	if !detect.CommandExists("timedatectl") {
		return false, "unknown"
	}

	out, err := exec.Command("timedatectl", "status").Output()
	if err != nil {
		return false, "unknown"
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "System clock synchronized:") {
			synced = strings.Contains(line, "yes")
		}

		if strings.HasPrefix(line, "NTP service:") {
			if !strings.Contains(line, "active") {
				synced = false
			}
		}
	}

	offset = "0s" // Simplified, could parse from chronyc or ntpq
	return
}
