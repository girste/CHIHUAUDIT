package report

import (
	"fmt"
	"strings"

	"chihuaudit/checks"
)

func PrintText(results *checks.AuditResults) {
	fmt.Println("=== CHIHUAUDIT REPORT ===")
	fmt.Printf("Timestamp: %s\n", results.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("Hostname: %s\n", results.Hostname)
	fmt.Printf("OS: %s\n", results.OS)
	fmt.Printf("Kernel: %s\n", results.Kernel)
	fmt.Printf("Uptime: %s\n", results.Uptime)
	fmt.Println()

	printSecurity(results.Security)
	printServices(results.Services)
	printResources(results.Resources)
	printStorage(results.Storage)
	printDatabase(results.Database)
	printDocker(results.Docker)
	printSystem(results.System)
	printLogs(results.Logs)
	printNetwork(results.Network)
	printBackups(results.Backups)
	printSystemTuning(results.Tuning)

	printSummary(results)
}

func printSecurity(s checks.Security) {
	fmt.Println("--- 1. SECURITY ---")
	fmt.Printf("Firewall: %s\n", s.Firewall)
	if s.FirewallRules > 0 {
		fmt.Printf("Firewall Rules: %d\n", s.FirewallRules)
	}
	
	// SSH Details
	fmt.Printf("SSH: %s\n", s.SSHStatus)
	if s.SSHPort > 0 {
		fmt.Printf("SSH Port: %d\n", s.SSHPort)
	}
	
	// SSH Password Auth
	switch s.SSHPasswordAuth {
	case "yes":
		fmt.Printf("SSH Password Auth: enabled (⚠️ consider key-only)\n")
	case "no":
		fmt.Printf("SSH Password Auth: disabled ✓\n")
	case "skipped":
		fmt.Printf("SSH Password Auth: skipped (run with sudo)\n")
	case "not specified":
		fmt.Printf("SSH Password Auth: not specified (⚠️ defaults to enabled)\n")
	}
	
	// SSH Root Login
	switch s.SSHRootLogin {
	case "no", "prohibit-password":
		fmt.Printf("SSH Root Login: %s ✓\n", s.SSHRootLogin)
	case "yes", "without-password":
		fmt.Printf("SSH Root Login: %s (⚠️ not recommended)\n", s.SSHRootLogin)
	case "skipped":
		fmt.Printf("SSH Root Login: skipped (run with sudo)\n")
	case "not specified":
		fmt.Printf("SSH Root Login: not specified (⚠️ defaults to enabled)\n")
	default:
		if s.SSHRootLogin != "" {
			fmt.Printf("SSH Root Login: %s\n", s.SSHRootLogin)
		}
	}
	
	// Ports
	if len(s.ExternalPorts) > 0 {
		fmt.Printf("External Ports: %v\n", s.ExternalPorts)
	}
	if len(s.LocalOnlyPorts) > 0 {
		fmt.Printf("Localhost-Only Ports: %v\n", s.LocalOnlyPorts)
	}
	if len(s.UnusualPorts) > 0 {
		fmt.Printf("Unusual Ports: %v (⚠️ non-standard)\n", s.UnusualPorts)
	}
	
	// SSL
	if s.SSLCerts > 0 {
		fmt.Printf("SSL Certificates: %d (%s)\n", s.SSLCerts, s.SSLExpires)
	}
	
	// Connections
	if s.ExternalConns > 0 {
		fmt.Printf("External Connections: %d\n", s.ExternalConns)
	}
	if len(s.TopIPs) > 0 {
		ips := make([]string, len(s.TopIPs))
		for i, ip := range s.TopIPs {
			ips[i] = fmt.Sprintf("%s (%d)", ip.IP, ip.Count)
		}
		fmt.Printf("Top IPs: %s\n", strings.Join(ips, ", "))
	}
	
	// Other security metrics
	if s.SUIDCount > 0 {
		fmt.Printf("SUID Binaries: %d\n", s.SUIDCount)
	}
	if s.WorldWritable > 0 {
		fmt.Printf("World-Writable Files: %d (⚠️)\n", s.WorldWritable)
	}
	
	// Fail2ban
	if s.Fail2banStatus == "active" {
		fmt.Printf("Fail2ban: active")
		if s.Fail2banJails > 0 {
			fmt.Printf(" (%d jails)", s.Fail2banJails)
		}
		if s.Fail2banBanned > 0 {
			fmt.Printf(", %d IPs banned", s.Fail2banBanned)
		}
		fmt.Println()
	}
	
	// Shell users
	if len(s.ShellUsers) > 0 {
		fmt.Printf("Shell Users: %d", len(s.ShellUsers))
		if len(s.ShellUsers) <= 5 {
			fmt.Printf(" (%s)", strings.Join(s.ShellUsers, ", "))
		}
		fmt.Println()
	}
	
	// Root UID users
	if s.RootUsers > 1 {
		fmt.Printf("⚠️  Root UID Users: %d (multiple root accounts!)\n", s.RootUsers)
	}
	
	// Recent /etc modifications
	if s.RecentEtcMods > 0 {
		fmt.Printf("Recent /etc Mods: %d (last 7 days)\n", s.RecentEtcMods)
	}
	
	fmt.Println()
}

func printServices(s checks.Services) {
	fmt.Println("--- 2. SERVICES ---")
	fmt.Printf("Total Running: %d\n", s.TotalRunning)
	fmt.Printf("Failed: %d\n", s.Failed)
	if s.WebServer != "" {
		fmt.Printf("Web: %s (%s)\n", s.WebServer, s.WebStatus)
	}
	if s.Database != "" {
		fmt.Printf("Database: %s (%s)\n", s.Database, s.DBStatus)
	}
	fmt.Println()
}

func printResources(r checks.Resources) {
	fmt.Println("--- 3. RESOURCES ---")
	fmt.Printf("CPU Load: %.2f, %.2f, %.2f\n", r.CPULoad1, r.CPULoad5, r.CPULoad15)
	if r.MemTotal > 0 {
		fmt.Printf("Memory: %.1f/%.1f GB (%.0f%%)\n",
			float64(r.MemUsed)/1024/1024/1024,
			float64(r.MemTotal)/1024/1024/1024,
			r.MemPercent)
	}
	for _, mount := range r.DiskMounts {
		fmt.Printf("Disk %s: %.1f/%.1f GB (%.0f%%)\n",
			mount.Path,
			float64(mount.Used)/1024/1024/1024,
			float64(mount.Total)/1024/1024/1024,
			mount.Percent)
	}
	fmt.Println()
}

func printStorage(s checks.Storage) {
	fmt.Println("--- 4. STORAGE ---")
	if s.DiskHealth != "" {
		fmt.Printf("Disk Health: %s\n", s.DiskHealth)
	}
	if len(s.InodeUsage) > 0 {
		for _, inode := range s.InodeUsage {
			fmt.Printf("Inode %s: %.0f%%\n", inode.Mount, inode.Percent)
		}
	}
	fmt.Println()
}

func printDatabase(d checks.Database) {
	fmt.Println("--- 5. DATABASES ---")
	if d.PostgreSQL.Available {
		fmt.Printf("PostgreSQL: %d databases, %s total\n",
			d.PostgreSQL.Databases, d.PostgreSQL.TotalSize)
		if d.PostgreSQL.Connections > 0 {
			fmt.Printf("  Connections: %d/%d\n", d.PostgreSQL.Connections, d.PostgreSQL.ConnLimit)
		}
	}
	if d.MySQL.Available {
		fmt.Printf("MySQL: %d databases, %s total\n",
			d.MySQL.Databases, d.MySQL.TotalSize)
	}
	if d.Redis.Available {
		fmt.Printf("Redis: %s memory, %d clients\n", d.Redis.Memory, d.Redis.Clients)
	}
	if !d.PostgreSQL.Available && !d.MySQL.Available && !d.Redis.Available {
		fmt.Println("No databases found")
	}
	fmt.Println()
}

func printDocker(d checks.Docker) {
	fmt.Println("--- 6. DOCKER ---")
	if d.Available {
		fmt.Printf("Containers: %d running, %d stopped\n", d.Running, d.Stopped)
		fmt.Printf("Images: %d (%s)\n", d.Images, d.ImagesSize)
		fmt.Printf("Volumes: %d (%s)\n", d.Volumes, d.VolumesSize)
	} else {
		fmt.Println("Docker not available")
	}
	fmt.Println()
}

func printSystem(s checks.System) {
	fmt.Println("--- 7. CONFIGURATION ---")
	fmt.Printf("Listening Ports: %d\n", s.ListeningPorts)
	fmt.Printf("Active Connections: %d\n", s.ActiveConns)
	fmt.Printf("Cron Jobs: %d\n", s.CronJobs)
	fmt.Printf("Systemd Timers: %d\n", s.SystemdTimers)
	if s.PendingUpdates > 0 {
		fmt.Printf("Pending Updates: %d (%d security)\n", s.PendingUpdates, s.SecurityUpdates)
	}
	fmt.Println()
}

func printLogs(l checks.Logs) {
	fmt.Println("--- 8. LOGS ---")
	fmt.Printf("Syslog Errors: %d (last 24h)\n", l.SyslogErrors)
	fmt.Printf("SSH Failed: %d attempts\n", l.SSHFailed)
	if len(l.SSHFailedIPs) > 0 {
		fmt.Printf("  From IPs: %s\n", strings.Join(l.SSHFailedIPs[:min(3, len(l.SSHFailedIPs))], ", "))
	}
	fmt.Println()
}

func printNetwork(n checks.Network) {
	fmt.Println("--- 9. NETWORK ---")
	if n.DNSResolution != "" {
		fmt.Printf("DNS: %s (%s)\n", n.DNSResolution, n.DNSLatency)
	}
	if n.PingLatency != "" {
		fmt.Printf("Latency: %s\n", n.PingLatency)
	}
	for _, iface := range n.Interfaces {
		fmt.Printf("Interface %s: %s (%s)\n", iface.Name, iface.IP, iface.Status)
	}
	fmt.Println()
}

func printBackups(b checks.Backups) {
	fmt.Println("--- 10. BACKUPS ---")
	if b.DirExists {
		fmt.Printf("Backup Dir: %s\n", b.BackupDir)
		fmt.Printf("Last Backup: %s\n", b.LastBackup)
		fmt.Printf("Size: %s\n", b.BackupSize)
	} else {
		fmt.Println("Backup Dir: none found")
		fmt.Println("Last Backup: none found")
		fmt.Println("Size: 0")
	}
	
	if b.CronJobs > 0 {
		fmt.Printf("Cron Backup Jobs: %d active\n", b.CronJobs)
	}
	
	fmt.Println()
}

func printSummary(r *checks.AuditResults) {
	fmt.Println("--- SUMMARY ---")
	fmt.Printf("Total Checks: %d\n", r.TotalChecks)
	if len(r.Skipped) > 0 {
		fmt.Printf("Skipped: %d (%s)\n", len(r.Skipped), strings.Join(r.Skipped, ", "))
	}
	if len(r.Notes) > 0 {
		fmt.Println("Notes:")
		for _, note := range r.Notes {
			fmt.Printf("  %s\n", note)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func printSystemTuning(t checks.SystemTuning) {
fmt.Println("--- 11. SYSTEM TUNING ---")

// NTP/Time Sync
if t.NTPStatus != "" {
fmt.Printf("Time Sync: %s", t.NTPStatus)
if t.NTPService != "" && t.NTPService != "unknown" {
fmt.Printf(" (NTP: %s)", t.NTPService)
}
fmt.Println()
}

// File Descriptors
if t.FileDescriptorsMax > 0 {
fmt.Printf("File Descriptors: %d / %d", t.FileDescriptorsCurrent, t.FileDescriptorsMax)
if t.FileDescriptorsMax > 0 {
percent := float64(t.FileDescriptorsCurrent) / float64(t.FileDescriptorsMax) * 100
fmt.Printf(" (%.1f%%)", percent)
}
fmt.Println()
}

// Sysctl Parameters
if len(t.SysctlParams) > 0 {
fmt.Println("Kernel Parameters:")
keys := []string{
"net.core.somaxconn",
"net.ipv4.tcp_max_syn_backlog",
"net.ipv4.ip_local_port_range",
"vm.swappiness",
}
for _, key := range keys {
if val, ok := t.SysctlParams[key]; ok {
fmt.Printf("  %s = %s\n", key, val)
}
}
}

fmt.Println()
}
