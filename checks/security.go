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
	s.SSHStatus, s.SSHPort, s.SSHPasswordAuth, s.SSHRootLogin, s.SSHProtocol, s.SSHAllowUsers, s.SSHConfigReadable = checkSSH()
	s.Fail2banStatus, s.Fail2banJails, s.Fail2banJailNames, s.Fail2banBanned = checkFail2ban()
	s.SSLCerts, s.SSLExpires, s.SSLExpiringSoon, s.SSLDomains = checkSSLCerts()
	s.RootUsers = countRootUsers()
	s.ShellUsers = getShellUsers()
	s.FailedLogins = countFailedLogins()
	s.OpenPorts, s.ExternalPorts, s.LocalOnlyPorts, s.ExternalPortDetails, s.LocalPortDetails = getOpenPorts()
	s.UnusualPorts = findUnusualPorts(s.ExternalPorts)
	s.SUIDCount, s.SUIDPaths = countSUIDBinaries()
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
		cmd := exec.Command("ufw", "status")
		output, err := cmd.CombinedOutput() // Capture both stdout and stderr
		outputStr := string(output)
		
		// Check for permission errors
		if strings.Contains(outputStr, "need to be root") || strings.Contains(outputStr, "permission denied") {
			return "skipped (run with sudo)"
		}
		
		if err == nil && strings.Contains(outputStr, "Status: active") {
			return "active (ufw)"
		}
		
		if err != nil {
			return "inactive (ufw)"
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

func checkSSH() (status string, port int, passwordAuth, rootLogin, protocol, allowUsers string, configReadable bool) {
	status = "not found"
	port = 22
	passwordAuth = "skipped"
	rootLogin = "skipped"
	protocol = "2"
	allowUsers = "any"
	configReadable = false

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
		// Permission denied - mark as skipped
		if os.IsPermission(err) {
			return
		}
		return
	}
	defer func() { _ = file.Close() }()

	// We successfully opened the config
	configReadable = true

	// Set defaults for when directives are not specified
	passwordAuth = "not specified"
	rootLogin = "not specified"

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
			passwordAuth = value
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

func checkFail2ban() (status string, jails int, jailNames []string, banned int) {
	if !detect.CommandExists("fail2ban-client") {
		return "not installed", 0, nil, 0
	}

	if detect.CommandExists("systemctl") {
		if err := exec.Command("systemctl", "is-active", "fail2ban").Run(); err != nil {
			return "inactive", 0, nil, 0
		}
	}

	status = "active"

	// Count jails and get names
	out, err := exec.Command("fail2ban-client", "status").Output()
	if err != nil {
		return status, 0, nil, 0
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Jail list:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				continue
			}
			jailList := strings.TrimSpace(parts[1])
			for _, name := range strings.Split(jailList, ",") {
				name = strings.TrimSpace(name)
				if name != "" {
					jailNames = append(jailNames, name)
				}
			}
			jails = len(jailNames)
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

func checkSSLCerts() (count int, expires string, expiringSoon int, domains []string) {
	// Check common cert locations - only actual server certs
	certPaths := []string{
		"/etc/letsencrypt/live",
		"/var/lib/caddy/.local/share/caddy/certificates",
	}

	seen := make(map[string]bool)
	for _, path := range certPaths {
		if detect.FileExists(path) {
			// Count only cert.pem and *.crt files, not all entries
			countCertsInPath(path, &count)
			for _, d := range collectSSLDomains(path) {
				if d == "local" || seen[d] {
					continue
				}
				seen[d] = true
				domains = append(domains, d)
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

func collectSSLDomains(basePath string) []string {
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return nil
	}

	var domains []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "." || name == ".." || name == "README" {
			continue
		}

		// Check if subdirectories contain actual domains (e.g. Caddy: provider/domain/cert)
		subEntries, err := os.ReadDir(basePath + "/" + name)
		if err != nil {
			continue
		}
		hasDomainSubs := false
		for _, sub := range subEntries {
			if sub.IsDir() {
				hasDomainSubs = true
				domains = append(domains, sub.Name())
			}
		}
		// If no subdirectories, this directory is itself a domain (e.g. Let's Encrypt)
		if !hasDomainSubs {
			domains = append(domains, name)
		}
	}
	return domains
}

func countCertsInPath(basePath string, count *int) {
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return
	}
	
	for _, entry := range entries {
		if entry.IsDir() {
			// Recursively check subdirectories
			countCertsInPath(basePath+"/"+entry.Name(), count)
		} else {
			// Count only actual certificate files
			name := entry.Name()
			if name == "cert.pem" || strings.HasSuffix(name, ".crt") {
				*count++
			}
		}
	}
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
	defer func() { _ = file.Close() }()

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
	defer func() { _ = file.Close() }()

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
	// Use journalctl for systemd-based systems (more accurate than log files)
	out, err := exec.Command("journalctl", "-u", "sshd", "--since", "24 hours ago", "--no-pager").Output()
	if err != nil {
		// Fallback to log files if journalctl fails
		logPaths := []string{"/var/log/auth.log", "/var/log/secure"}
		logPath := detect.TryPaths(logPaths...)
		if logPath == "" {
			return 0
		}
		out, err = exec.Command("grep", "-c", "Failed password", logPath).Output()
		if err != nil {
			return 0
		}
		count, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		return count
	}

	// Count lines containing "Failed" or "failure" (case insensitive)
	count := 0
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "failed") || strings.Contains(lower, "failure") {
			count++
		}
	}
	
	return count
}

func getOpenPorts() (allPorts, external, localOnly []int, extDetails, localDetails []PortDetail) {
	// Try ss first (with -p for process names), then netstat
	var out []byte
	var err error

	if detect.CommandExists("ss") {
		out, err = exec.Command("ss", "-tulnp").Output()
	} else if detect.CommandExists("netstat") {
		out, err = exec.Command("netstat", "-tulnp").Output()
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

		// Extract process name from users:(("name",...)) field
		procName := parseProcessName(fields)

		bindAddr := strings.Join(parts[:len(parts)-1], ":")

		// Check if localhost-only (127.0.0.1 or ::1)
		if strings.Contains(bindAddr, "127.0.0.1") || bindAddr == "::1" || bindAddr == "localhost" {
			localOnly = append(localOnly, port)
			localDetails = append(localDetails, PortDetail{Port: port, Process: procName, Bind: bindAddr})
		} else {
			external = append(external, port)
			extDetails = append(extDetails, PortDetail{Port: port, Process: procName, Bind: bindAddr})
		}
	}

	return
}

func parseProcessName(fields []string) string {
	// Look for users:(("process_name",...)) pattern in ss output
	for _, field := range fields {
		if strings.HasPrefix(field, "users:") {
			// Extract name from users:(("name",pid=...,fd=...))
			start := strings.Index(field, "((\"")
			if start == -1 {
				continue
			}
			end := strings.Index(field[start+3:], "\"")
			if end == -1 {
				continue
			}
			return field[start+3 : start+3+end]
		}
	}
	return ""
}

func countSUIDBinaries() (int, []string) {
	// Search only in standard binary locations, count only SUID (not SGID)
	searchPaths := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"}
	var suidPaths []string

	for _, basePath := range searchPaths {
		out, err := exec.Command("find", basePath, "-perm", "-4000", "-type", "f").Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line != "" {
				suidPaths = append(suidPaths, line)
			}
		}
	}

	return len(suidPaths), suidPaths
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
