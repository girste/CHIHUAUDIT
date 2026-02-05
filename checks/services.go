package checks

import (
	"os/exec"
	"strings"

	"chihuaudit/detect"
)

func CheckServices() Services {
	s := Services{}

	if detect.DetectInitSystem() == "systemd" {
		s.TotalRunning, s.Failed, s.AutoRestart = getSystemdStats()
	}

	s.WebServer, s.WebStatus = checkWebServer()
	s.Database, s.DBStatus = checkDatabase()
	s.AppServer, s.AppStatus = checkAppServer()
	s.DockerStatus = checkDockerService()
	s.SSHStatus = checkSSHService()
	s.CronStatus = checkCronService()

	return s
}

func getSystemdStats() (running, failed, autoRestart int) {
	if !detect.CommandExists("systemctl") {
		return
	}

	// Count running services
	out, err := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend").Output()
	if err == nil {
		running = len(strings.Split(strings.TrimSpace(string(out)), "\n"))
	}

	// Count failed services
	out, err = exec.Command("systemctl", "list-units", "--type=service", "--state=failed", "--no-pager", "--no-legend").Output()
	if err == nil {
		result := strings.TrimSpace(string(out))
		if result != "" {
			failed = len(strings.Split(result, "\n"))
		}
	}

	// Count services with auto-restart
	out, err = exec.Command("systemctl", "show", "*", "--property=Restart", "--no-pager").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Restart=") && !strings.Contains(line, "Restart=no") {
				autoRestart++
			}
		}
	}

	return
}

func checkWebServer() (name, status string) {
	servers := []string{"nginx", "apache2", "httpd", "caddy", "lighttpd"}

	for _, srv := range servers {
		if detect.CommandExists("systemctl") {
			if err := exec.Command("systemctl", "is-active", srv).Run(); err == nil {
				return srv, "active"
			}
		}
	}

	return "none", "not found"
}

func checkDatabase() (name, status string) {
	databases := map[string][]string{
		"postgresql": {"postgresql", "postgres"},
		"mysql":      {"mysql", "mysqld"},
		"mariadb":    {"mariadb"},
		"mongodb":    {"mongodb", "mongod"},
		"redis":      {"redis", "redis-server"},
	}

	for dbName, services := range databases {
		for _, srv := range services {
			if detect.CommandExists("systemctl") {
				if err := exec.Command("systemctl", "is-active", srv).Run(); err == nil {
					return dbName, "active"
				}
			}
		}
	}

	return "none", "not found"
}

func checkAppServer() (name, status string) {
	servers := []string{"gunicorn", "uwsgi", "pm2"}

	for _, srv := range servers {
		if detect.CommandExists("systemctl") {
			if err := exec.Command("systemctl", "is-active", srv).Run(); err == nil {
				return srv, "active"
			}
		}

		// Check if process is running
		if detect.CommandExists("pgrep") {
			if err := exec.Command("pgrep", "-x", srv).Run(); err == nil {
				return srv, "active"
			}
		}
	}

	return "none", "not found"
}

func checkDockerService() string {
	if !detect.CommandExists("systemctl") {
		return "not found"
	}

	if err := exec.Command("systemctl", "is-active", "docker").Run(); err == nil {
		return "active"
	}

	return "inactive"
}

func checkSSHService() string {
	if !detect.CommandExists("systemctl") {
		return "unknown"
	}

	services := []string{"ssh", "sshd"}
	for _, srv := range services {
		if err := exec.Command("systemctl", "is-active", srv).Run(); err == nil {
			return "active"
		}
	}

	return "inactive"
}

func checkCronService() string {
	if !detect.CommandExists("systemctl") {
		return "unknown"
	}

	services := []string{"cron", "crond"}
	for _, srv := range services {
		if err := exec.Command("systemctl", "is-active", srv).Run(); err == nil {
			return "active"
		}
	}

	return "inactive"
}
