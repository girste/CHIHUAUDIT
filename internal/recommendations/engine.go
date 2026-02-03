package recommendations

import "strings"

// ForDrift generates recommendations for baseline drift changes
func ForDrift(analyzerName, field, changeType string) string {
	switch analyzerName {
	case "firewall":
		if changeType == "added" {
			return "Review new firewall rule. Ensure it follows principle of least privilege."
		}
		if changeType == "removed" {
			return "Verify firewall rule removal was intentional and doesn't expose services."
		}
		return "Audit firewall configuration changes for security impact."

	case "ssh":
		return "Review SSH configuration change. Ensure it doesn't weaken authentication."

	case "services":
		if changeType == "added" {
			return "Verify new service is authorized and properly configured."
		}
		if changeType == "removed" {
			return "Confirm service removal was intentional."
		}
		return "Check service configuration for security implications."

	case "users":
		if changeType == "added" {
			return "Verify new user account is authorized. Check sudo/admin privileges."
		}
		if changeType == "removed" {
			return "Confirm user removal was intentional."
		}
		return "Audit user account changes."

	case "docker":
		return "Review Docker configuration changes for security impact."

	case "fail2ban":
		return "Check fail2ban configuration to ensure protection is active."

	case "mac":
		return "Verify MAC (AppArmor/SELinux) policy changes are intentional."

	case "sudo":
		return "Review sudoers changes. Remove NOPASSWD entries if unauthorized."

	case "cron":
		return "Audit cron job changes. Verify scheduled tasks are authorized."

	case "permissions":
		return "Review file permission changes. Ensure sensitive files remain protected."

	case "processes":
		return "Investigate new/changed processes. Verify they are expected services."

	default:
		return "Review system change and verify it was authorized."
	}
}

// ForIssue generates actionable advice for security issues found during audit
func ForIssue(category, message string) string {
	switch category {
	case "firewall":
		return "Enable UFW firewall: sudo ufw enable && sudo ufw default deny incoming"
	
	case "ssh":
		if strings.Contains(message, "Root") {
			return "Disable root SSH: edit /etc/ssh/sshd_config and set PermitRootLogin no"
		}
		if strings.Contains(message, "password") {
			return "Disable password auth: set PasswordAuthentication no in sshd_config"
		}
		return "Harden SSH configuration following CIS benchmarks"
	
	case "intrusion_prevention", "fail2ban":
		return "Install and enable fail2ban: sudo apt install fail2ban && sudo systemctl enable fail2ban"
	
	case "updates":
		return "Apply security updates: sudo apt update && sudo apt upgrade"
	
	case "containers", "docker":
		return "Avoid privileged containers. Use --cap-drop=ALL and add only needed capabilities"
	
	case "sudo":
		return "Review and remove NOPASSWD entries from sudoers configuration"
	
	case "cron":
		return "Review all cron jobs and remove any unauthorized or suspicious entries"
	
	case "permissions":
		return "Fix file permissions — sensitive files must not be readable/writable by unauthorized users"
	
	case "users":
		if strings.Contains(message, "UID 0") {
			return "Remove or reassign UID 0 from non-root users immediately"
		}
		if strings.Contains(message, "weak password") {
			return "Upgrade password hashes to SHA-512: use passwd to reset affected accounts"
		}
		return "Audit user accounts and remove unauthorized or stale accounts"
	
	case "kernel":
		return "Apply kernel hardening: review /proc/sys parameters and set secure defaults in /etc/sysctl.d/"
	
	case "mac":
		return "Enable AppArmor or SELinux for mandatory access control"
	
	case "processes":
		if strings.Contains(message, "miner") || strings.Contains(message, "mining") {
			return "Terminate cryptocurrency miner immediately and investigate compromise"
		}
		if strings.Contains(message, "/tmp") {
			return "Investigate process running from /tmp — likely malicious"
		}
		return "Review running processes and terminate any unauthorized services"
	
	case "performance":
		if strings.Contains(message, "CPU") {
			return "Investigate running processes with top/htop and optimize or kill resource hogs"
		}
		if strings.Contains(message, "RAM") || strings.Contains(message, "memory") {
			return "Review memory-intensive processes or add more RAM"
		}
		if strings.Contains(message, "disk") || strings.Contains(message, "Disk") {
			return "Free disk space or expand storage volume"
		}
		return "Monitor system performance and optimize resource usage"
	
	default:
		return "Review the issue and take appropriate remediation action"
	}
}
