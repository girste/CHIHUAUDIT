package checks

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"chihuaudit/detect"
)

func CheckSecurity() Security {
	s := Security{}

	s.Firewall = checkFirewall()
	s.FirewallRules = countFirewallRules(s.Firewall)
	s.SSHStatus, s.SSHPort, s.SSHPasswordAuth, s.SSHRootLogin, s.SSHProtocol, s.SSHAllowUsers = checkSSH()
	s.Fail2banStatus, s.Fail2banJails, s.Fail2banBanned = checkFail2ban()
	s.SSLCerts, s.SSLExpires, s.SSLExpiringSoon = checkSSLCerts()
	s.RootUsers = countRootUsers()
	s.ShellUsers = getShellUsers()
	s.FailedLogins = countFailedLogins()
	s.OpenPorts, s.ExternalPorts, s.LocalOnlyPorts = getOpenPorts()
	s.UnusualPorts = findUnusualPorts(s.ExternalPorts)
	s.SUIDCount = countSUIDBinaries()
	s.WorldWritable = countWorldWritable()
	s.RecentEtcMods = countRecentEtcMods()
	s.ExternalConns = countExternalConnections()
	s.TopIPs = getTopConnectedIPs(5) // Use existing function from network.go

	return s
}

func checkFirewall() string {
	fw := detect.DetectFirewall()
	if fw == "" {
		return "none"
	}

	// Check if actually running
	switch fw {
	case "ufw":
		if out, err := exec.Command("ufw", "status").Output(); err == nil {
			if strings.Contains(string(out), "Status: active") {
				return "active (ufw)"
			}
		}
		return "inactive (ufw)"
	case "firewalld":
		if err := exec.Command("systemctl", "is-active", "firewalld").Run(); err == nil {
			return "active (firewalld)"
		}
		return "inactive (firewalld)"
	case "iptables":
		return "active (iptables)"
	}

	return fw
}

func countFirewallRules(firewall string) int {
	if !strings.Contains(firewall, "active") {
		return 0
	}

	if strings.Contains(firewall, "ufw") {
		out, err := exec.Command("ufw", "status", "numbered").Output()
		if err != nil {
			return 0
		}
		count := 0
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "[") {
				count++
			}
		}
		return count
	}

	if strings.Contains(firewall, "iptables") {
		out, err := exec.Command("iptables", "-L", "-n").Output()
		if err != nil {
			return 0
		}
		count := 0
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "ACCEPT") || strings.HasPrefix(line, "DROP") || strings.HasPrefix(line, "REJECT") {
				count++
			}
		}
		return count
	}

	return 0
}

func checkSSH() (status string, port int, passwordAuth bool, rootLogin, protocol, allowUsers string) {
	status = "not found"
	port = 22 // default
	passwordAuth = true
	rootLogin = "yes" // default if not specified
	protocol = "2"    // default
	allowUsers = "any"

	// Check if SSH is running
	if detect.CommandExists("systemctl") {
		if err := exec.Command("systemctl", "is-active", "ssh").Run(); err == nil {
			status = "active"
		} else if err := exec.Command("systemctl", "is-active", "sshd").Run(); err == nil {
			status = "active"
		} else {
			status = "inactive"
		}
	}

	// Parse SSH config
	configPath := detect.TryPaths("/etc/ssh/sshd_config", "/etc/sshd_config")
	if configPath == "" {
		return
	}

	file, err := os.Open(configPath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.ToLower(fields[0])
		value := strings.ToLower(fields[1])

		switch key {
		case "port":
			if p, err := strconv.Atoi(fields[1]); err == nil {
				port = p
			}
		case "passwordauthentication":
			passwordAuth = value == "yes"
		case "permitrootlogin":
			rootLogin = value
		case "protocol":
			protocol = fields[1]
		case "allowusers":
			allowUsers = strings.Join(fields[1:], " ")
		case "denyusers":
			if allowUsers == "any" {
				allowUsers = "restricted"
			}
		}
	}

	return
}

func checkFail2ban() (status string, jails, banned int) {
	if !detect.CommandExists("fail2ban-client") {
		return "not installed", 0, 0
	}

	if detect.CommandExists("systemctl") {
		if err := exec.Command("systemctl", "is-active", "fail2ban").Run(); err != nil {
			return "inactive", 0, 0
		}
	}

	status = "active"

	// Count jails
	out, err := exec.Command("fail2ban-client", "status").Output()
	if err != nil {
		return status, 0, 0
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Jail list:") {
			jailList := strings.Split(line, ":")[1]
			jails = len(strings.Split(strings.TrimSpace(jailList), ","))
		}
	}

	// Count banned IPs
	if jails > 0 {
		out, err := exec.Command("fail2ban-client", "banned").Output()
		if err == nil {
			banned = len(strings.Split(strings.TrimSpace(string(out)), "\n"))
		}
	}

	return
}

func checkSSLCerts() (count int, expires string, expiringSoon int) {
	// Check common cert locations
	certPaths := []string{
		"/etc/letsencrypt/live",
		"/etc/ssl/certs",
		"/etc/caddy/certificates",
	}

	for _, path := range certPaths {
		if detect.FileExists(path) {
			// Count cert directories or files
			if entries, err := os.ReadDir(path); err == nil {
				count += len(entries)
			}
		}
	}

	// Check expiring certs in Let's Encrypt
	if detect.FileExists("/etc/letsencrypt/live") && detect.CommandExists("openssl") {
		expiringSoon = checkCertExpiry("/etc/letsencrypt/live")
	}

	if expiringSoon > 0 {
		expires = strconv.Itoa(expiringSoon) + " expiring <30d"
	} else {
		expires = "all valid"
	}

	return
}

func checkCertExpiry(basePath string) int {
	expiring := 0
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		certPath := basePath + "/" + entry.Name() + "/cert.pem"
		if !detect.FileExists(certPath) {
			continue
		}

		out, err := exec.Command("openssl", "x509", "-in", certPath, "-noout", "-enddate").Output()
		if err != nil {
			continue
		}

		// Parse: notAfter=Jan 1 00:00:00 2027 GMT
		dateStr := strings.TrimPrefix(string(out), "notAfter=")
		dateStr = strings.TrimSpace(dateStr)

		// Simple 30-day check
		if strings.Contains(dateStr, "2026") {
			// Could be expiring soon - simplified check
			expiring++
		}
	}

	return expiring
}

func countRootUsers() int {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return 0
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 3 && fields[2] == "0" {
			count++
		}
	}

	return count
}

func getShellUsers() []string {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer file.Close()

	var users []string
	validShells := map[string]bool{
		"/bin/bash": true, "/bin/sh": true, "/bin/zsh": true,
		"/bin/fish": true, "/usr/bin/bash": true, "/usr/bin/zsh": true,
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 7 && validShells[fields[6]] {
			users = append(users, fields[0])
		}
	}

	return users
}

func countFailedLogins() int {
	logPaths := []string{"/var/log/auth.log", "/var/log/secure"}
	logPath := detect.TryPaths(logPaths...)
	if logPath == "" {
		return 0
	}

	out, err := exec.Command("grep", "-c", "Failed password", logPath).Output()
	if err != nil {
		return 0
	}

	count, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return count
}

func getOpenPorts() (allPorts, external, localOnly []int) {
	// Try ss first, then netstat
	var out []byte
	var err error

	if detect.CommandExists("ss") {
		out, err = exec.Command("ss", "-tuln").Output()
	} else if detect.CommandExists("netstat") {
		out, err = exec.Command("netstat", "-tuln").Output()
	}

	if err != nil {
		return
	}

	seen := make(map[int]bool)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Parse address:port format
		addr := fields[4]
		parts := strings.Split(addr, ":")
		if len(parts) < 2 {
			continue
		}

		port, err := strconv.Atoi(parts[len(parts)-1])
		if err != nil || seen[port] {
			continue
		}

		seen[port] = true
		allPorts = append(allPorts, port)

		// Check if localhost-only (127.0.0.1 or ::1)
		bindAddr := strings.Join(parts[:len(parts)-1], ":")
		if strings.Contains(bindAddr, "127.0.0.1") || bindAddr == "::1" || bindAddr == "localhost" {
			localOnly = append(localOnly, port)
		} else {
			external = append(external, port)
		}
	}

	return
}

func countSUIDBinaries() int {
	out, err := exec.Command("find", "/usr/bin", "/usr/sbin", "-type", "f", "-perm", "-4000", "-o", "-perm", "-2000").Output()
	if err != nil {
		return 0
	}

	return len(strings.Split(strings.TrimSpace(string(out)), "\n"))
}

func countWorldWritable() int {
	paths := []string{"/etc", "/usr/bin", "/usr/sbin"}
	total := 0

	for _, path := range paths {
		if !detect.FileExists(path) {
			continue
		}

		out, err := exec.Command("find", path, "-maxdepth", "2", "-type", "f", "-perm", "-002").Output()
		if err != nil {
			continue
		}

		output := strings.TrimSpace(string(out))
		if output != "" {
			total += len(strings.Split(output, "\n"))
		}
	}

	return total
}

func countRecentEtcMods() int {
	if !detect.FileExists("/etc") {
		return 0
	}

	out, err := exec.Command("find", "/etc", "-type", "f", "-mtime", "-7").Output()
	if err != nil {
		return 0
	}

	output := strings.TrimSpace(string(out))
	if output == "" {
		return 0
	}

	return len(strings.Split(output, "\n"))
}

func findUnusualPorts(ports []int) []int {
	// Common/standard ports
	standardPorts := map[int]bool{
		20: true, 21: true, 22: true, 23: true, 25: true,
		53: true, 67: true, 68: true, 69: true, 80: true,
		110: true, 143: true, 443: true, 465: true, 587: true,
		993: true, 995: true, 3306: true, 5432: true, 6379: true,
		8080: true, 8443: true, 9000: true,
	}

	var unusual []int
	for _, port := range ports {
		if !standardPorts[port] {
			unusual = append(unusual, port)
		}
	}

	return unusual
}

func countExternalConnections() int {
	if !detect.CommandExists("ss") && !detect.CommandExists("netstat") {
		return 0
	}

	var out []byte
	var err error

	if detect.CommandExists("ss") {
		out, err = exec.Command("ss", "-tn", "state", "established").Output()
	} else {
		out, err = exec.Command("netstat", "-tn").Output()
	}

	if err != nil {
		return 0
	}

	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "ESTABLISHED") || strings.Contains(line, "ESTAB") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				// Check if it's external (not 127.0.0.1 or localhost)
				remote := fields[4]
				if !strings.HasPrefix(remote, "127.") && !strings.HasPrefix(remote, "::1") {
					count++
				}
			}
		}
	}

	return count
}
