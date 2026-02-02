package cis

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
)

// Checker provides CIS control verification functions
type Checker struct {
	ctx            context.Context
	whitelist      *config.Whitelist
	sshConfigCache string
	sshConfigRead  bool
}

// NewChecker creates a new Checker instance
func NewChecker(ctx context.Context, wl *config.Whitelist) *Checker {
	return &Checker{ctx: ctx, whitelist: wl}
}

// WithWhitelistCheck wraps a CheckFunc to check the whitelist before executing
func (c *Checker) WithWhitelistCheck(controlID string, check CheckFunc) CheckFunc {
	return func() (ComplianceStatus, string) {
		if c.whitelist != nil && c.whitelist.IsCISExcepted(controlID) {
			return StatusPass, "Check skipped (whitelisted in configuration)"
		}
		return check()
	}
}

// CheckModuleDisabled returns a check function for verifying a kernel module is disabled
func (c *Checker) CheckModuleDisabled(module string) CheckFunc {
	return func() (ComplianceStatus, string) {
		// Check if module is loaded using word boundary matching
		result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "lsmod")
		if result != nil && result.Success {
			// Use regex for exact module name match (first column of lsmod)
			re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(module) + `\s`)
			if re.MatchString(result.Stdout) {
				// Context-aware: Check if module is required by installed software
				contextMsg := c.getModuleContext(module)
				if contextMsg != "" {
					return StatusPass, contextMsg
				}
				return StatusFail, fmt.Sprintf("Module %s is currently loaded", module)
			}
		}

		// Check modprobe configuration
		result, _ = system.RunCommand(c.ctx, system.TimeoutShort, "modprobe", "-n", "-v", module)
		if result != nil {
			output := result.Stdout + result.Stderr
			// Module is disabled if install points to /bin/false or /bin/true
			if strings.Contains(output, "/bin/false") || strings.Contains(output, "/bin/true") {
				return StatusPass, fmt.Sprintf("Module %s is disabled via modprobe", module)
			}
			// Module not found in kernel
			if strings.Contains(output, "not found") || strings.Contains(output, "Module "+module+" not found") {
				return StatusPass, fmt.Sprintf("Module %s is not available in kernel", module)
			}
		}

		// Check blacklist files in /etc/modprobe.d/
		if entries, err := os.ReadDir("/etc/modprobe.d"); err == nil {
			for _, e := range entries {
				if !strings.HasSuffix(e.Name(), ".conf") {
					continue
				}
				data, err := os.ReadFile("/etc/modprobe.d/" + e.Name())
				if err != nil {
					continue
				}
				content := string(data)
				// Check for blacklist or install directive
				blacklistRe := regexp.MustCompile(`(?m)^\s*blacklist\s+` + regexp.QuoteMeta(module) + `\s*$`)
				installRe := regexp.MustCompile(`(?m)^\s*install\s+` + regexp.QuoteMeta(module) + `\s+/bin/(false|true)`)
				if blacklistRe.MatchString(content) || installRe.MatchString(content) {
					return StatusPass, fmt.Sprintf("Module %s is disabled in %s", module, e.Name())
				}
			}
		}

		return StatusFail, fmt.Sprintf("Module %s is not disabled", module)
	}
}

// getModuleContext checks if a kernel module is required by installed software
func (c *Checker) getModuleContext(module string) string {
	switch module {
	case "squashfs":
		// Check if snap is installed
		if system.CommandExists("snap") {
			snapResult, _ := system.RunCommand(c.ctx, system.TimeoutShort, "snap", "list")
			if snapResult != nil && snapResult.Success && len(strings.TrimSpace(snapResult.Stdout)) > 0 {
				return "Module squashfs is loaded (required by snap packages)"
			}
		}
	}
	return ""
}

// CheckTmpPartition verifies /tmp is a separate partition
func (c *Checker) CheckTmpPartition() (ComplianceStatus, string) {
	result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "findmnt", "-n", "/tmp")
	if result != nil && result.Success && strings.TrimSpace(result.Stdout) != "" {
		return StatusPass, "/tmp is mounted as separate partition: " + strings.Split(result.Stdout, " ")[0]
	}

	// Check if tmp.mount is enabled
	result, _ = system.RunCommand(c.ctx, system.TimeoutShort, "systemctl", "is-enabled", "tmp.mount")
	if result != nil && result.Success && strings.TrimSpace(result.Stdout) == "enabled" {
		return StatusPass, "/tmp is configured via systemd tmp.mount"
	}

	return StatusFail, "/tmp is not a separate partition"
}

// CheckMountOption returns a check function for verifying mount options
func (c *Checker) CheckMountOption(mountpoint, option string) CheckFunc {
	return func() (ComplianceStatus, string) {
		result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "findmnt", "-n", "-o", "OPTIONS", mountpoint)
		if result == nil || !result.Success || strings.TrimSpace(result.Stdout) == "" {
			return StatusNA, fmt.Sprintf("%s is not a separate mount point", mountpoint)
		}

		options := strings.TrimSpace(result.Stdout)
		if strings.Contains(options, option) {
			return StatusPass, fmt.Sprintf("%s has %s option: %s", mountpoint, option, options)
		}
		return StatusFail, fmt.Sprintf("%s does not have %s option: %s", mountpoint, option, options)
	}
}

// CheckBootloaderPassword verifies GRUB bootloader password is set
func (c *Checker) CheckBootloaderPassword() (ComplianceStatus, string) {
	grubCfgPaths := []string{
		"/boot/grub/grub.cfg",
		"/boot/grub2/grub.cfg",
		"/boot/efi/EFI/ubuntu/grub.cfg",
	}

	for _, path := range grubCfgPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			// Try with sudo
			result, _ := system.RunCommandSudo(c.ctx, system.TimeoutShort, "cat", path)
			if result != nil && result.Success {
				data = []byte(result.Stdout)
			} else {
				continue
			}
		}

		if strings.Contains(string(data), "set superusers") {
			return StatusPass, "Bootloader password is configured"
		}
	}

	return StatusFail, "Bootloader password is not set"
}

// CheckBootloaderPermissions verifies GRUB config file permissions
func (c *Checker) CheckBootloaderPermissions() (ComplianceStatus, string) {
	grubCfgPaths := []string{
		"/boot/grub/grub.cfg",
		"/boot/grub2/grub.cfg",
	}

	for _, path := range grubCfgPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		mode := info.Mode().Perm()
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		// Check owner is root and permissions are 0600 or stricter
		if stat.Uid == 0 && stat.Gid == 0 && mode <= 0600 {
			return StatusPass, fmt.Sprintf("%s has correct permissions: %04o, owner root:root", path, mode)
		}
		return StatusFail, fmt.Sprintf("%s has insecure permissions: %04o, uid=%d, gid=%d", path, mode, stat.Uid, stat.Gid)
	}

	return StatusNA, "GRUB configuration file not found"
}

// CheckASLR verifies ASLR is enabled
func (c *Checker) CheckASLR() (ComplianceStatus, string) {
	result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "sysctl", "-n", "kernel.randomize_va_space")
	if result != nil && result.Success {
		value := strings.TrimSpace(result.Stdout)
		if value == "2" {
			return StatusPass, "ASLR is fully enabled (kernel.randomize_va_space = 2)"
		}
		return StatusFail, fmt.Sprintf("ASLR is not fully enabled (kernel.randomize_va_space = %s)", value)
	}
	return StatusFail, "Could not check ASLR status"
}

// CheckPackageNotInstalled returns a check function for verifying a package is NOT installed
func (c *Checker) CheckPackageNotInstalled(pkg string) CheckFunc {
	return func() (ComplianceStatus, string) {
		result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "dpkg", "-s", pkg)
		if result != nil && result.Success && strings.Contains(result.Stdout, "Status: install ok installed") {
			return StatusFail, fmt.Sprintf("Package %s is installed", pkg)
		}
		return StatusPass, fmt.Sprintf("Package %s is not installed", pkg)
	}
}

// CheckPackageInstalled returns a check function for verifying a package is installed
func (c *Checker) CheckPackageInstalled(pkg string) CheckFunc {
	return func() (ComplianceStatus, string) {
		result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "dpkg", "-s", pkg)
		if result != nil && result.Success && strings.Contains(result.Stdout, "Status: install ok installed") {
			return StatusPass, fmt.Sprintf("Package %s is installed", pkg)
		}
		return StatusFail, fmt.Sprintf("Package %s is not installed", pkg)
	}
}

// CheckIPv6Disabled verifies IPv6 is disabled (if not required)
func (c *Checker) CheckIPv6Disabled() (ComplianceStatus, string) {
	// Check sysctl
	result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "sysctl", "-n", "net.ipv6.conf.all.disable_ipv6")
	if result != nil && result.Success {
		if strings.TrimSpace(result.Stdout) == "1" {
			return StatusPass, "IPv6 is disabled via sysctl"
		}
	}

	// Check GRUB for ipv6.disable=1
	grubDefault, _ := os.ReadFile("/etc/default/grub")
	if strings.Contains(string(grubDefault), "ipv6.disable=1") {
		return StatusPass, "IPv6 is disabled via GRUB"
	}

	// IPv6 is enabled - this might be intentional
	return StatusFail, "IPv6 is enabled. If IPv6 is required, this can be marked as N/A"
}

// CheckSysctl returns a check function for verifying sysctl value
func (c *Checker) CheckSysctl(param, expected string) CheckFunc {
	return func() (ComplianceStatus, string) {
		result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "sysctl", "-n", param)
		if result != nil && result.Success {
			actual := strings.TrimSpace(result.Stdout)
			if actual == expected {
				return StatusPass, fmt.Sprintf("%s = %s", param, actual)
			}
			return StatusFail, fmt.Sprintf("%s = %s (expected %s)", param, actual, expected)
		}
		return StatusFail, fmt.Sprintf("Could not read %s", param)
	}
}

// CheckIPForwarding returns a check function that is context-aware of containers
// IP forwarding is required by Docker/Podman/LXC, so we don't flag it as a failure if container runtime is active
// Also checks whitelist for manual exceptions
func (c *Checker) CheckIPForwarding() CheckFunc {
	return func() (ComplianceStatus, string) {
		// Check whitelist first
		if c.whitelist != nil && c.whitelist.IsCISExcepted("3.2.2") {
			return StatusPass, "IP forwarding check skipped (whitelisted in configuration)"
		}

		result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "sysctl", "-n", "net.ipv4.ip_forward")
		if result == nil || !result.Success {
			return StatusFail, "Could not read net.ipv4.ip_forward"
		}

		actual := strings.TrimSpace(result.Stdout)
		if actual == "0" {
			return StatusPass, "IP forwarding is disabled (net.ipv4.ip_forward = 0)"
		}

		// IP forwarding is enabled - check if container runtime is active
		containerRuntime := c.detectContainerRuntime()
		if containerRuntime != "" {
			return StatusPass, fmt.Sprintf("IP forwarding is enabled (net.ipv4.ip_forward = 1, required by %s)", containerRuntime)
		}

		return StatusFail, "IP forwarding is enabled (net.ipv4.ip_forward = 1)"
	}
}

// detectContainerRuntime checks if any container runtime is active
// Uses centralized patterns from config for extensibility
func (c *Checker) detectContainerRuntime() string {
	// Try common container runtimes via systemd
	runtimes := []string{"docker", "podman", "lxd", "containerd"}
	for _, runtime := range runtimes {
		if system.CommandExists(runtime) {
			result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "systemctl", "is-active", runtime)
			if result != nil && strings.TrimSpace(result.Stdout) == "active" {
				return runtime
			}
		}
	}

	// Check for LXC (might not have systemd service)
	if system.CommandExists("lxc-ls") {
		result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "lxc-ls")
		if result != nil && result.Success && len(strings.TrimSpace(result.Stdout)) > 0 {
			return "LXC"
		}
	}

	return ""
}

// CheckFirewallInstalled verifies a firewall package is installed
func (c *Checker) CheckFirewallInstalled() (ComplianceStatus, string) {
	firewalls := []string{"ufw", "firewalld", "iptables"}
	for _, fw := range firewalls {
		if system.CommandExists(fw) {
			// Check if package is actually installed
			result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "dpkg", "-s", fw)
			if result != nil && result.Success && strings.Contains(result.Stdout, "Status: install ok installed") {
				return StatusPass, fmt.Sprintf("Firewall %s is installed", fw)
			}
		}
	}
	return StatusFail, "No firewall package installed (ufw, firewalld, or iptables)"
}

// CheckFirewallDefaultDeny verifies firewall has default deny policy
func (c *Checker) CheckFirewallDefaultDeny() (ComplianceStatus, string) {
	// Check UFW
	if system.CommandExists("ufw") {
		result, _ := system.RunCommandSudo(c.ctx, system.TimeoutShort, "ufw", "status", "verbose")
		if result != nil && result.Success {
			if strings.Contains(result.Stdout, "Status: active") {
				if strings.Contains(result.Stdout, "Default: deny (incoming)") {
					return StatusPass, "UFW has default deny incoming policy"
				}
				return StatusFail, "UFW does not have default deny incoming policy"
			}
			return StatusFail, "UFW is not active"
		}
	}

	// Check firewalld
	if system.CommandExists("firewall-cmd") {
		result, _ := system.RunCommandSudo(c.ctx, system.TimeoutShort, "firewall-cmd", "--get-default-zone")
		if result != nil && result.Success {
			zone := strings.TrimSpace(result.Stdout)
			// Check if zone has DROP or REJECT as target
			targetResult, _ := system.RunCommandSudo(c.ctx, system.TimeoutShort, "firewall-cmd", "--zone="+zone, "--get-target")
			if targetResult != nil {
				target := strings.TrimSpace(targetResult.Stdout)
				if target == "DROP" || target == "REJECT" {
					return StatusPass, fmt.Sprintf("Firewalld zone %s has %s target", zone, target)
				}
			}
			return StatusFail, fmt.Sprintf("Firewalld zone %s does not have deny/drop default", zone)
		}
	}

	// Check iptables
	if system.CommandExists("iptables") {
		result, _ := system.RunCommandSudo(c.ctx, system.TimeoutShort, "iptables", "-L", "INPUT", "-n")
		if result != nil && result.Success {
			if strings.Contains(result.Stdout, "policy DROP") || strings.Contains(result.Stdout, "policy REJECT") {
				return StatusPass, "iptables INPUT chain has DROP/REJECT policy"
			}
		}
	}

	return StatusFail, "No firewall with default deny policy found"
}

// CheckFirewallRulesForOpenPorts verifies firewall rules exist for open ports
func (c *Checker) CheckFirewallRulesForOpenPorts() (ComplianceStatus, string) {
	// Get listening ports
	result, _ := system.RunCommand(c.ctx, system.TimeoutShort, "ss", "-tuln")
	if result == nil || !result.Success {
		return StatusNA, "Could not check listening ports"
	}

	// This is a heuristic check - just verify firewall is active
	if system.CommandExists("ufw") {
		ufwResult, _ := system.RunCommandSudo(c.ctx, system.TimeoutShort, "ufw", "status")
		if ufwResult != nil && strings.Contains(ufwResult.Stdout, "Status: active") {
			return StatusPass, "UFW is active, review rules for open ports"
		}
	}

	if system.CommandExists("firewall-cmd") {
		fwResult, _ := system.RunCommandSudo(c.ctx, system.TimeoutShort, "firewall-cmd", "--state")
		if fwResult != nil && strings.TrimSpace(fwResult.Stdout) == "running" {
			return StatusPass, "Firewalld is running, review rules for open ports"
		}
	}

	return StatusFail, "Firewall not active - cannot verify rules for open ports"
}

// CheckServiceEnabled returns a check function for verifying a service is enabled
func (c *Checker) CheckServiceEnabled(service string) CheckFunc {
	return func() (ComplianceStatus, string) {
		enabledResult, _ := system.RunCommand(c.ctx, system.TimeoutShort, "systemctl", "is-enabled", service)
		activeResult, _ := system.RunCommand(c.ctx, system.TimeoutShort, "systemctl", "is-active", service)

		enabled := enabledResult != nil && strings.TrimSpace(enabledResult.Stdout) == "enabled"
		active := activeResult != nil && strings.TrimSpace(activeResult.Stdout) == "active"

		if enabled && active {
			return StatusPass, fmt.Sprintf("Service %s is enabled and active", service)
		}
		if enabled && !active {
			return StatusFail, fmt.Sprintf("Service %s is enabled but not active", service)
		}
		if !enabled && active {
			return StatusFail, fmt.Sprintf("Service %s is active but not enabled", service)
		}
		return StatusFail, fmt.Sprintf("Service %s is not enabled or active", service)
	}
}

// CheckRsyslogFilePermissions verifies rsyslog default file permissions
func (c *Checker) CheckRsyslogFilePermissions() (ComplianceStatus, string) {
	files := []string{"/etc/rsyslog.conf"}

	// Check rsyslog.d directory
	if entries, err := os.ReadDir("/etc/rsyslog.d"); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				files = append(files, "/etc/rsyslog.d/"+e.Name())
			}
		}
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "$FileCreateMode 0640") ||
			strings.Contains(string(data), "$FileCreateMode 0600") {
			return StatusPass, fmt.Sprintf("rsyslog FileCreateMode is configured in %s", f)
		}
	}

	return StatusFail, "rsyslog FileCreateMode not configured (should be 0640 or stricter)"
}

// CheckJournaldCompress verifies journald compression is enabled
func (c *Checker) CheckJournaldCompress() (ComplianceStatus, string) {
	data, err := os.ReadFile("/etc/systemd/journald.conf")
	if err != nil {
		return StatusFail, "Could not read /etc/systemd/journald.conf"
	}

	re := regexp.MustCompile(`(?m)^Compress\s*=\s*yes`)
	if re.MatchString(string(data)) {
		return StatusPass, "Journald Compress=yes is configured"
	}

	// Check if not explicitly set (default is yes)
	reNo := regexp.MustCompile(`(?m)^Compress\s*=\s*no`)
	if reNo.MatchString(string(data)) {
		return StatusFail, "Journald Compress=no is set"
	}

	// Default behavior - compression is enabled by default in journald
	return StatusPass, "Journald compression uses default (enabled)"
}

// CheckJournaldStorage verifies journald persistent storage
func (c *Checker) CheckJournaldStorage() (ComplianceStatus, string) {
	data, err := os.ReadFile("/etc/systemd/journald.conf")
	if err != nil {
		return StatusFail, "Could not read /etc/systemd/journald.conf"
	}

	re := regexp.MustCompile(`(?m)^Storage\s*=\s*persistent`)
	if re.MatchString(string(data)) {
		return StatusPass, "Journald Storage=persistent is configured"
	}

	// Check if /var/log/journal exists (auto-persistent)
	if _, err := os.Stat("/var/log/journal"); err == nil {
		return StatusPass, "Journald uses persistent storage (/var/log/journal exists)"
	}

	return StatusFail, "Journald Storage is not set to persistent"
}

// CheckFilePermissions returns a check function for verifying file permissions
// maxMode specifies the maximum allowed permissions - actual mode must not have any bits
// that aren't in maxMode (i.e., must be equally or more restrictive)
func (c *Checker) CheckFilePermissions(path string, maxMode os.FileMode, uid, gid uint32) CheckFunc {
	return func() (ComplianceStatus, string) {
		info, err := os.Stat(path)
		if err != nil {
			return StatusNA, fmt.Sprintf("File %s not found", path)
		}

		mode := info.Mode().Perm()
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return StatusFail, fmt.Sprintf("Could not get ownership info for %s", path)
		}

		// Check permissions using bitwise comparison
		// Mode is OK if it doesn't have any bits set that aren't in maxMode
		// Example: maxMode=0600, mode=0400 is OK (stricter), mode=0644 is NOT OK (has group/other read)
		extraBits := mode &^ maxMode
		permOk := extraBits == 0
		uidOk := stat.Uid == uid
		gidOk := stat.Gid == gid

		if permOk && uidOk && gidOk {
			return StatusPass, fmt.Sprintf("%s: mode=%04o, uid=%d, gid=%d", path, mode, stat.Uid, stat.Gid)
		}

		issues := []string{}
		if !permOk {
			issues = append(issues, fmt.Sprintf("mode=%04o (max allowed %04o)", mode, maxMode))
		}
		if !uidOk {
			issues = append(issues, fmt.Sprintf("uid=%d (expected %d)", stat.Uid, uid))
		}
		if !gidOk {
			issues = append(issues, fmt.Sprintf("gid=%d (expected %d)", stat.Gid, gid))
		}
		return StatusFail, fmt.Sprintf("%s: %s", path, strings.Join(issues, ", "))
	}
}

// CheckShadowPermissions verifies /etc/shadow permissions (special case for shadow group)
func (c *Checker) CheckShadowPermissions() (ComplianceStatus, string) {
	info, err := os.Stat("/etc/shadow")
	if err != nil {
		return StatusFail, "Could not stat /etc/shadow"
	}

	mode := info.Mode().Perm()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return StatusFail, "Could not get ownership info for /etc/shadow"
	}

	// /etc/shadow should be owned by root:shadow (gid usually 42) or root:root
	// Permissions should be 640 or stricter
	permOk := mode <= 0640
	uidOk := stat.Uid == 0

	if permOk && uidOk {
		return StatusPass, fmt.Sprintf("/etc/shadow: mode=%04o, uid=%d, gid=%d", mode, stat.Uid, stat.Gid)
	}

	return StatusFail, fmt.Sprintf("/etc/shadow: mode=%04o (expected <=0640), uid=%d", mode, stat.Uid)
}

// CheckGshadowPermissions verifies /etc/gshadow permissions
func (c *Checker) CheckGshadowPermissions() (ComplianceStatus, string) {
	info, err := os.Stat("/etc/gshadow")
	if err != nil {
		return StatusNA, "/etc/gshadow not found"
	}

	mode := info.Mode().Perm()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return StatusFail, "Could not get ownership info for /etc/gshadow"
	}

	permOk := mode <= 0640
	uidOk := stat.Uid == 0

	if permOk && uidOk {
		return StatusPass, fmt.Sprintf("/etc/gshadow: mode=%04o, uid=%d, gid=%d", mode, stat.Uid, stat.Gid)
	}

	return StatusFail, fmt.Sprintf("/etc/gshadow: mode=%04o (expected <=0640), uid=%d", mode, stat.Uid)
}

// getSudoersFiles returns list of sudoers config files (main + sudoers.d/*.conf)
func (c *Checker) getSudoersFiles() []string {
	files := []string{"/etc/sudoers"}
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			name := e.Name()
			// Skip hidden files, README, and files with ~ or . extensions
			if strings.HasPrefix(name, ".") ||
				strings.HasPrefix(name, "README") ||
				strings.HasSuffix(name, "~") ||
				strings.Contains(name, ".") && !strings.HasSuffix(name, ".conf") {
				continue
			}
			files = append(files, "/etc/sudoers.d/"+name)
		}
	}
	return files
}

// CheckSudoUsePty verifies sudo uses pty
func (c *Checker) CheckSudoUsePty() (ComplianceStatus, string) {
	files := c.getSudoersFiles()

	for _, f := range files {
		result, _ := system.RunCommandSudo(c.ctx, system.TimeoutShort, "cat", f)
		if result != nil && result.Success {
			re := regexp.MustCompile(`(?m)^\s*Defaults\s+.*use_pty`)
			if re.MatchString(result.Stdout) {
				return StatusPass, fmt.Sprintf("Defaults use_pty found in %s", f)
			}
		}
	}

	return StatusFail, "Defaults use_pty not configured in sudoers"
}

// CheckSudoLogFile verifies sudo log file is configured
func (c *Checker) CheckSudoLogFile() (ComplianceStatus, string) {
	files := c.getSudoersFiles()

	for _, f := range files {
		result, _ := system.RunCommandSudo(c.ctx, system.TimeoutShort, "cat", f)
		if result != nil && result.Success {
			re := regexp.MustCompile(`(?m)^\s*Defaults\s+.*logfile\s*=`)
			if re.MatchString(result.Stdout) {
				return StatusPass, fmt.Sprintf("Defaults logfile found in %s", f)
			}
		}
	}

	return StatusFail, "Defaults logfile not configured in sudoers"
}

// getSSHConfig returns the effective SSH configuration, cached for performance
func (c *Checker) getSSHConfig() string {
	// Return cached config if already read
	if c.sshConfigRead {
		return c.sshConfigCache
	}

	c.sshConfigRead = true

	// Try sshd -T first (effective config)
	result, _ := system.RunCommandSudo(c.ctx, system.TimeoutShort, "sshd", "-T")
	if result != nil && result.Success {
		c.sshConfigCache = strings.ToLower(result.Stdout)
		return c.sshConfigCache
	}

	// Fall back to reading config file
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		result, _ := system.RunCommandSudo(c.ctx, system.TimeoutShort, "cat", "/etc/ssh/sshd_config")
		if result != nil && result.Success {
			c.sshConfigCache = strings.ToLower(result.Stdout)
			return c.sshConfigCache
		}
	}
	c.sshConfigCache = strings.ToLower(string(data))
	return c.sshConfigCache
}

// CheckSSHLogLevel verifies SSH LogLevel
func (c *Checker) CheckSSHLogLevel() (ComplianceStatus, string) {
	config := c.getSSHConfig()
	re := regexp.MustCompile(`(?m)^loglevel\s+(\S+)`)
	match := re.FindStringSubmatch(config)
	if len(match) > 1 {
		level := strings.ToUpper(match[1])
		if level == "INFO" || level == "VERBOSE" {
			return StatusPass, fmt.Sprintf("SSH LogLevel is %s", level)
		}
		return StatusFail, fmt.Sprintf("SSH LogLevel is %s (expected INFO or VERBOSE)", level)
	}
	// Default is INFO
	return StatusPass, "SSH LogLevel uses default (INFO)"
}

// CheckSSHX11Forwarding verifies X11 forwarding is disabled
func (c *Checker) CheckSSHX11Forwarding() (ComplianceStatus, string) {
	config := c.getSSHConfig()
	re := regexp.MustCompile(`(?m)^x11forwarding\s+(\S+)`)
	match := re.FindStringSubmatch(config)
	if len(match) > 1 {
		if match[1] == "no" {
			return StatusPass, "SSH X11Forwarding is disabled"
		}
		return StatusFail, "SSH X11Forwarding is enabled"
	}
	// Default varies by distribution
	return StatusFail, "SSH X11Forwarding not explicitly disabled"
}

// CheckSSHMaxAuthTries verifies MaxAuthTries
func (c *Checker) CheckSSHMaxAuthTries() (ComplianceStatus, string) {
	config := c.getSSHConfig()
	re := regexp.MustCompile(`(?m)^maxauthtries\s+(\d+)`)
	match := re.FindStringSubmatch(config)
	if len(match) > 1 {
		tries, _ := strconv.Atoi(match[1])
		if tries <= 4 {
			return StatusPass, fmt.Sprintf("SSH MaxAuthTries is %d", tries)
		}
		return StatusFail, fmt.Sprintf("SSH MaxAuthTries is %d (expected <= 4)", tries)
	}
	// Default is 6
	return StatusFail, "SSH MaxAuthTries uses default (6), should be 4 or less"
}

// CheckSSHPermitRootLogin verifies root login is disabled
func (c *Checker) CheckSSHPermitRootLogin() (ComplianceStatus, string) {
	config := c.getSSHConfig()
	re := regexp.MustCompile(`(?m)^permitrootlogin\s+(\S+)`)
	match := re.FindStringSubmatch(config)
	if len(match) > 1 {
		if match[1] == "no" {
			return StatusPass, "SSH PermitRootLogin is disabled"
		}
		return StatusFail, fmt.Sprintf("SSH PermitRootLogin is %s (expected no)", match[1])
	}
	return StatusFail, "SSH PermitRootLogin not explicitly set to no"
}

// CheckSSHPermitEmptyPasswords verifies empty passwords are not permitted
func (c *Checker) CheckSSHPermitEmptyPasswords() (ComplianceStatus, string) {
	config := c.getSSHConfig()
	re := regexp.MustCompile(`(?m)^permitemptypasswords\s+(\S+)`)
	match := re.FindStringSubmatch(config)
	if len(match) > 1 {
		if match[1] == "no" {
			return StatusPass, "SSH PermitEmptyPasswords is disabled"
		}
		return StatusFail, "SSH PermitEmptyPasswords is enabled"
	}
	// Default is no
	return StatusPass, "SSH PermitEmptyPasswords uses default (no)"
}

// CheckPasswordMaxDays verifies password expiration
func (c *Checker) CheckPasswordMaxDays() (ComplianceStatus, string) {
	data, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return StatusFail, "Could not read /etc/login.defs"
	}

	re := regexp.MustCompile(`(?m)^PASS_MAX_DAYS\s+(\d+)`)
	match := re.FindStringSubmatch(string(data))
	if len(match) > 1 {
		days, _ := strconv.Atoi(match[1])
		if days <= 365 && days > 0 {
			return StatusPass, fmt.Sprintf("PASS_MAX_DAYS is %d", days)
		}
		return StatusFail, fmt.Sprintf("PASS_MAX_DAYS is %d (expected <= 365)", days)
	}
	return StatusFail, "PASS_MAX_DAYS not configured"
}

// CheckPasswordMinDays verifies minimum days between password changes
func (c *Checker) CheckPasswordMinDays() (ComplianceStatus, string) {
	data, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return StatusFail, "Could not read /etc/login.defs"
	}

	re := regexp.MustCompile(`(?m)^PASS_MIN_DAYS\s+(\d+)`)
	match := re.FindStringSubmatch(string(data))
	if len(match) > 1 {
		days, _ := strconv.Atoi(match[1])
		if days >= 1 {
			return StatusPass, fmt.Sprintf("PASS_MIN_DAYS is %d", days)
		}
		return StatusFail, fmt.Sprintf("PASS_MIN_DAYS is %d (expected >= 1)", days)
	}
	return StatusFail, "PASS_MIN_DAYS not configured or is 0"
}

// CheckPasswordWarnAge verifies password warning days
func (c *Checker) CheckPasswordWarnAge() (ComplianceStatus, string) {
	data, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return StatusFail, "Could not read /etc/login.defs"
	}

	re := regexp.MustCompile(`(?m)^PASS_WARN_AGE\s+(\d+)`)
	match := re.FindStringSubmatch(string(data))
	if len(match) > 1 {
		days, _ := strconv.Atoi(match[1])
		if days >= 7 {
			return StatusPass, fmt.Sprintf("PASS_WARN_AGE is %d", days)
		}
		return StatusFail, fmt.Sprintf("PASS_WARN_AGE is %d (expected >= 7)", days)
	}
	return StatusFail, "PASS_WARN_AGE not configured"
}

// CheckShadowedPasswords verifies all accounts use shadowed passwords
func (c *Checker) CheckShadowedPasswords() (ComplianceStatus, string) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return StatusFail, "Could not read /etc/passwd"
	}

	unshadowed := []string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) >= 2 && parts[1] != "x" {
			unshadowed = append(unshadowed, parts[0])
		}
	}

	if len(unshadowed) > 0 {
		return StatusFail, fmt.Sprintf("Accounts without shadowed passwords: %s", strings.Join(unshadowed, ", "))
	}
	return StatusPass, "All accounts use shadowed passwords"
}

// CheckNoEmptyPasswords verifies no accounts have empty passwords
func (c *Checker) CheckNoEmptyPasswords() (ComplianceStatus, string) {
	result, _ := system.RunCommandSudo(c.ctx, system.TimeoutShort, "cat", "/etc/shadow")
	if result == nil || !result.Success {
		return StatusFail, "Could not read /etc/shadow"
	}

	emptyPwd := []string{}
	scanner := bufio.NewScanner(strings.NewReader(result.Stdout))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) >= 2 && parts[1] == "" {
			emptyPwd = append(emptyPwd, parts[0])
		}
	}

	if len(emptyPwd) > 0 {
		return StatusFail, fmt.Sprintf("Accounts with empty passwords: %s", strings.Join(emptyPwd, ", "))
	}
	return StatusPass, "No accounts have empty passwords"
}

// CheckGroupsExist verifies all groups in passwd exist in group
func (c *Checker) CheckGroupsExist() (ComplianceStatus, string) {
	passwdData, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return StatusFail, "Could not read /etc/passwd"
	}

	groupData, err := os.ReadFile("/etc/group")
	if err != nil {
		return StatusFail, "Could not read /etc/group"
	}

	// Build map of existing GIDs
	gids := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(groupData)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) >= 3 {
			gids[parts[2]] = true
		}
	}

	// Check all passwd GIDs exist
	missing := []string{}
	scanner = bufio.NewScanner(strings.NewReader(string(passwdData)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) >= 4 {
			gid := parts[3]
			if !gids[gid] {
				missing = append(missing, fmt.Sprintf("%s(gid=%s)", parts[0], gid))
			}
		}
	}

	if len(missing) > 0 {
		return StatusFail, fmt.Sprintf("Users with non-existent GIDs: %s", strings.Join(missing, ", "))
	}
	return StatusPass, "All groups in /etc/passwd exist in /etc/group"
}

// CheckNoDuplicateUIDs verifies no duplicate UIDs exist
func (c *Checker) CheckNoDuplicateUIDs() (ComplianceStatus, string) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return StatusFail, "Could not read /etc/passwd"
	}

	uids := make(map[string][]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) >= 3 {
			uid := parts[2]
			uids[uid] = append(uids[uid], parts[0])
		}
	}

	duplicates := []string{}
	for uid, users := range uids {
		if len(users) > 1 {
			duplicates = append(duplicates, fmt.Sprintf("UID %s: %s", uid, strings.Join(users, ", ")))
		}
	}

	if len(duplicates) > 0 {
		return StatusFail, fmt.Sprintf("Duplicate UIDs found: %s", strings.Join(duplicates, "; "))
	}
	return StatusPass, "No duplicate UIDs found"
}

// CheckNoDuplicateGIDs verifies no duplicate GIDs exist
func (c *Checker) CheckNoDuplicateGIDs() (ComplianceStatus, string) {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return StatusFail, "Could not read /etc/group"
	}

	gids := make(map[string][]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) >= 3 {
			gid := parts[2]
			gids[gid] = append(gids[gid], parts[0])
		}
	}

	duplicates := []string{}
	for gid, groups := range gids {
		if len(groups) > 1 {
			duplicates = append(duplicates, fmt.Sprintf("GID %s: %s", gid, strings.Join(groups, ", ")))
		}
	}

	if len(duplicates) > 0 {
		return StatusFail, fmt.Sprintf("Duplicate GIDs found: %s", strings.Join(duplicates, "; "))
	}
	return StatusPass, "No duplicate GIDs found"
}

// CheckRootOnlyUID0 verifies only root has UID 0
func (c *Checker) CheckRootOnlyUID0() (ComplianceStatus, string) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return StatusFail, "Could not read /etc/passwd"
	}

	uid0Users := []string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) >= 3 && parts[2] == "0" {
			uid0Users = append(uid0Users, parts[0])
		}
	}

	if len(uid0Users) == 1 && uid0Users[0] == "root" {
		return StatusPass, "Only root has UID 0"
	}

	nonRoot := []string{}
	for _, user := range uid0Users {
		if user != "root" {
			nonRoot = append(nonRoot, user)
		}
	}

	if len(nonRoot) > 0 {
		return StatusFail, fmt.Sprintf("Non-root users with UID 0: %s", strings.Join(nonRoot, ", "))
	}
	return StatusPass, "Only root has UID 0"
}
