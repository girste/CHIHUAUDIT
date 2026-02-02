package scanners

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/system"
)

// BackupVerificationResult is the result of a backup configuration audit
type BackupVerificationResult struct {
	ScanCompleted      bool              `json:"scan_completed"`
	ToolsInstalled     []BackupTool      `json:"tools_installed"`
	ScheduledBackups   []ScheduledBackup `json:"scheduled_backups"`
	BackupDestinations []BackupDest      `json:"backup_destinations"`
	Issues             []BackupIssue     `json:"issues"`
	Summary            BackupSummary     `json:"summary"`
	Recommendations    []string          `json:"recommendations"`
}

type BackupTool struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	Path      string `json:"path,omitempty"`
}

type ScheduledBackup struct {
	Type        string `json:"type"`
	Schedule    string `json:"schedule"`
	Command     string `json:"command,omitempty"`
	Destination string `json:"destination,omitempty"`
	LastRun     string `json:"last_run,omitempty"`
}

type BackupDest struct {
	Type      string `json:"type"`
	Path      string `json:"path"`
	Encrypted bool   `json:"encrypted"`
	Writable  bool   `json:"writable"`
}

type BackupIssue struct {
	Severity string `json:"severity"`
	Type     string `json:"type"`
	Message  string `json:"message"`
}

type BackupSummary struct {
	ToolsCount        int  `json:"tools_count"`
	ScheduledCount    int  `json:"scheduled_count"`
	DestinationsCount int  `json:"destinations_count"`
	HasEncryption     bool `json:"has_encryption"`
	HasRemoteBackup   bool `json:"has_remote_backup"`
	IssuesCount       int  `json:"issues_count"`
}

// Backup tools to check
var backupTools = []struct {
	name    string
	binary  string
	version []string
}{
	{"restic", "restic", []string{"version"}},
	{"borg", "borg", []string{"--version"}},
	{"duplicity", "duplicity", []string{"--version"}},
	{"rsync", "rsync", []string{"--version"}},
	{"rclone", "rclone", []string{"version"}},
	{"duplicati", "duplicati-cli", []string{"help"}},
	{"borgmatic", "borgmatic", []string{"--version"}},
	{"rdiff-backup", "rdiff-backup", []string{"--version"}},
}

// VerifyBackupConfig audits backup and disaster recovery configuration
func VerifyBackupConfig(ctx context.Context) *BackupVerificationResult {
	result := &BackupVerificationResult{
		ScanCompleted:      true,
		ToolsInstalled:     []BackupTool{},
		ScheduledBackups:   []ScheduledBackup{},
		BackupDestinations: []BackupDest{},
		Issues:             []BackupIssue{},
		Recommendations:    []string{},
	}

	// Check installed backup tools
	for _, tool := range backupTools {
		bt := BackupTool{
			Name:      tool.name,
			Installed: false,
		}

		if path, err := findExecutable(tool.binary); err == nil {
			bt.Installed = true
			bt.Path = path

			// Get version
			cmdArgs := append([]string{tool.binary}, tool.version...)
			vResult, _ := system.RunCommand(ctx, system.TimeoutShort, cmdArgs...)
			if vResult != nil && vResult.Success {
				// Extract first line
				lines := strings.Split(vResult.Stdout, "\n")
				if len(lines) > 0 {
					bt.Version = strings.TrimSpace(lines[0])
				}
			}
		}

		result.ToolsInstalled = append(result.ToolsInstalled, bt)
	}

	// Count installed tools
	installedCount := 0
	for _, tool := range result.ToolsInstalled {
		if tool.Installed {
			installedCount++
		}
	}

	if installedCount == 0 {
		result.Issues = append(result.Issues, BackupIssue{
			Severity: "high",
			Type:     "no_backup_tools",
			Message:  "No backup tools installed",
		})
		result.Recommendations = append(result.Recommendations, "Install a backup tool: restic, borg, or duplicity")
	}

	// Check cron for backup jobs
	cronBackups := scanCronForBackups(ctx)
	result.ScheduledBackups = append(result.ScheduledBackups, cronBackups...)

	// Check systemd timers for backup jobs
	timerBackups := scanSystemdTimers(ctx)
	result.ScheduledBackups = append(result.ScheduledBackups, timerBackups...)

	if len(result.ScheduledBackups) == 0 {
		result.Issues = append(result.Issues, BackupIssue{
			Severity: "high",
			Type:     "no_scheduled_backups",
			Message:  "No scheduled backup jobs found",
		})
		result.Recommendations = append(result.Recommendations, "Configure scheduled backups via cron or systemd timers")
	}

	// Check backup destinations
	destinations := findBackupDestinations(ctx)
	result.BackupDestinations = destinations

	hasRemote := false
	hasEncrypted := false
	for _, dest := range destinations {
		if dest.Type == "remote" || dest.Type == "cloud" {
			hasRemote = true
		}
		if dest.Encrypted {
			hasEncrypted = true
		}
	}

	if !hasRemote {
		result.Issues = append(result.Issues, BackupIssue{
			Severity: "medium",
			Type:     "no_remote_backup",
			Message:  "No remote/offsite backup destination detected",
		})
		result.Recommendations = append(result.Recommendations, "Configure offsite backup (cloud, remote server) for disaster recovery")
	}

	if !hasEncrypted && len(destinations) > 0 {
		result.Issues = append(result.Issues, BackupIssue{
			Severity: "medium",
			Type:     "no_encryption",
			Message:  "Backup encryption not detected",
		})
		result.Recommendations = append(result.Recommendations, "Enable encryption for backups to protect sensitive data")
	}

	// Summary
	result.Summary = BackupSummary{
		ToolsCount:        installedCount,
		ScheduledCount:    len(result.ScheduledBackups),
		DestinationsCount: len(result.BackupDestinations),
		HasEncryption:     hasEncrypted,
		HasRemoteBackup:   hasRemote,
		IssuesCount:       len(result.Issues),
	}

	return result
}

func findExecutable(name string) (string, error) {
	// Check common paths
	paths := []string{
		"/usr/bin/" + name,
		"/usr/local/bin/" + name,
		"/bin/" + name,
		"/snap/bin/" + name,
	}

	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}

	// Try which
	return "", os.ErrNotExist
}

func scanCronForBackups(ctx context.Context) []ScheduledBackup {
	var backups []ScheduledBackup

	backupPatterns := []string{
		"restic", "borg", "borgmatic", "duplicity", "rsync", "rclone",
		"backup", "rdiff-backup", "duplicati",
	}

	// Check user crontab
	userCron, _ := system.RunCommand(ctx, system.TimeoutShort, "crontab", "-l")
	if userCron != nil && userCron.Success {
		backups = append(backups, parseCronEntries(userCron.Stdout, backupPatterns)...)
	}

	// Check /etc/crontab
	if content, err := os.ReadFile("/etc/crontab"); err == nil {
		backups = append(backups, parseCronEntries(string(content), backupPatterns)...)
	}

	// Check /etc/cron.d/
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join("/etc/cron.d", entry.Name())
			if content, err := os.ReadFile(path); err == nil {
				backups = append(backups, parseCronEntries(string(content), backupPatterns)...)
			}
		}
	}

	// Check cron.daily, cron.weekly, etc.
	cronDirs := []string{"/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}
	for _, dir := range cronDirs {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				for _, pattern := range backupPatterns {
					if strings.Contains(strings.ToLower(entry.Name()), pattern) {
						schedule := filepath.Base(dir)
						backups = append(backups, ScheduledBackup{
							Type:     "cron",
							Schedule: schedule,
							Command:  entry.Name(),
						})
						break
					}
				}
			}
		}
	}

	return backups
}

func parseCronEntries(content string, patterns []string) []ScheduledBackup {
	var backups []ScheduledBackup

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lineLower := strings.ToLower(line)
		for _, pattern := range patterns {
			if strings.Contains(lineLower, pattern) {
				// Extract schedule (first 5 fields for standard cron)
				fields := strings.Fields(line)
				schedule := ""
				command := line
				if len(fields) >= 6 {
					schedule = strings.Join(fields[:5], " ")
					command = strings.Join(fields[5:], " ")
				}

				backups = append(backups, ScheduledBackup{
					Type:     "cron",
					Schedule: schedule,
					Command:  command,
				})
				break
			}
		}
	}

	return backups
}

func scanSystemdTimers(ctx context.Context) []ScheduledBackup {
	var backups []ScheduledBackup

	backupPatterns := []string{
		"restic", "borg", "borgmatic", "duplicity", "backup", "rsync", "rclone",
	}

	// List timers
	result, _ := system.RunCommand(ctx, system.TimeoutShort, "systemctl", "list-timers", "--no-pager")
	if result == nil || !result.Success {
		return backups
	}

	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		lineLower := strings.ToLower(line)
		for _, pattern := range backupPatterns {
			if strings.Contains(lineLower, pattern) {
				// Parse timer line
				fields := strings.Fields(line)
				if len(fields) >= 6 {
					unitName := ""
					for _, f := range fields {
						if strings.HasSuffix(f, ".timer") {
							unitName = f
							break
						}
					}

					nextRun := ""
					if len(fields) >= 3 {
						nextRun = fields[0] + " " + fields[1]
					}

					backups = append(backups, ScheduledBackup{
						Type:     "systemd_timer",
						Schedule: nextRun,
						Command:  unitName,
					})
				}
				break
			}
		}
	}

	return backups
}

func findBackupDestinations(ctx context.Context) []BackupDest {
	var destinations []BackupDest

	// Check common local backup directories
	localDirs := []string{
		system.HostPath("/backup"),
		system.HostPath("/backups"),
		system.HostPath("/var/backup"),
		system.HostPath("/var/backups"),
		system.HostPath("/mnt/backup"),
		system.HostPath("/mnt/backups"),
	}

	for _, dir := range localDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			dest := BackupDest{
				Type:     "local",
				Path:     dir,
				Writable: isWritable(dir),
			}

			// Check for encryption indicators
			if hasEncryptedFiles(dir) {
				dest.Encrypted = true
			}

			destinations = append(destinations, dest)
		}
	}

	// Check home directory for backup configs
	home := os.Getenv("HOME")
	if home != "" {
		// Restic repositories
		if content, err := os.ReadFile(filepath.Join(home, ".config/restic/repos")); err == nil {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				destType := "local"
				if strings.HasPrefix(line, "s3:") || strings.HasPrefix(line, "b2:") ||
					strings.HasPrefix(line, "gs:") || strings.HasPrefix(line, "azure:") {
					destType = "cloud"
				} else if strings.Contains(line, "@") || strings.HasPrefix(line, "sftp:") {
					destType = "remote"
				}
				destinations = append(destinations, BackupDest{
					Type:      destType,
					Path:      line,
					Encrypted: true, // Restic always encrypts
				})
			}
		}

		// Borg repos
		if content, err := os.ReadFile(filepath.Join(home, ".config/borg/security")); err == nil {
			// Borg security dir exists, likely has repos configured
			destinations = append(destinations, BackupDest{
				Type:      "local",
				Path:      "borg repository detected",
				Encrypted: true, // Borg encrypts by default
			})
			_ = content
		}

		// Check rclone config for remote destinations
		rcloneConfig := filepath.Join(home, ".config/rclone/rclone.conf")
		if content, err := os.ReadFile(rcloneConfig); err == nil {
			// Parse rclone remotes
			remotePattern := regexp.MustCompile(`\[([^\]]+)\]`)
			matches := remotePattern.FindAllStringSubmatch(string(content), -1)
			for _, match := range matches {
				if len(match) > 1 {
					destinations = append(destinations, BackupDest{
						Type: "cloud",
						Path: "rclone:" + match[1],
					})
				}
			}
		}
	}

	return destinations
}

func isWritable(path string) bool {
	testFile := filepath.Join(path, ".backup_test_"+time.Now().Format("20060102150405"))
	if f, err := os.Create(testFile); err == nil {
		_ = f.Close()
		_ = os.Remove(testFile)
		return true
	}
	return false
}

func hasEncryptedFiles(dir string) bool {
	// Check for common encrypted backup indicators
	encryptedPatterns := []string{
		"*.gpg", "*.enc", "*.aes", "*.encrypted",
		"data", "index", "keys", // Restic/Borg structure
	}

	for _, pattern := range encryptedPatterns {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		if len(matches) > 0 {
			return true
		}
	}

	// Check for Restic/Borg repository structure
	if _, err := os.Stat(filepath.Join(dir, "config")); err == nil {
		if _, err := os.Stat(filepath.Join(dir, "data")); err == nil {
			return true
		}
	}

	return false
}
