package checks

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"chihuaudit/detect"
)

func CheckBackups() Backups {
	b := Backups{}

	backupPaths := []string{"/backup", "/var/backups", "/backups", "/opt/backups"}
	b.BackupDir = detect.TryPaths(backupPaths...)
	b.DirExists = b.BackupDir != ""

	if b.DirExists {
		b.LastBackup, b.BackupSize = getLastBackup(b.BackupDir)
		b.RecentFiles = getRecentBackupFiles(b.BackupDir, 3)
	}
	
	// Check for backup cron jobs even if no backup directory found
	b.CronJobs = checkBackupCronJobs()

	return b
}

func checkBackupCronJobs() int {
	count := 0
	
	// Check system cron directories
	cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}
	for _, dir := range cronDirs {
		out, err := exec.Command("grep", "-r", "-l", "-E", "backup|dump", dir).Output()
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			for _, line := range lines {
				if line != "" {
					count++
				}
			}
		}
	}
	
	// Check user crontabs
	out, err := exec.Command("crontab", "-l").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				if strings.Contains(line, "backup") || strings.Contains(line, "dump") {
					count++
				}
			}
		}
	}
	
	return count
}


func getLastBackup(dir string) (lastTime, size string) {
	// Find most recent backup file - both pattern matching
	patterns := []string{
		"-name", "*.sql",
		"-o", "-name", "*.sql.gz",
		"-o", "-name", "*.dump",
		"-o", "-name", "backup*.tar.gz",
		"-o", "-name", "backup*.tar",
	}

	args := append([]string{dir, "-type", "f"}, patterns...)
	args = append(args, "-mtime", "-30") // Only last 30 days
	
	out, err := exec.Command("find", args...).Output()
	if err != nil {
		return "none found", "0"
	}

	files := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(files) == 0 || files[0] == "" {
		return "none found", "0"
	}

	var mostRecent string
	var mostRecentTime time.Time

	for _, file := range files {
		if file == "" {
			continue
		}

		stat, err := os.Stat(file)
		if err != nil {
			continue
		}

		if mostRecent == "" || stat.ModTime().After(mostRecentTime) {
			mostRecent = file
			mostRecentTime = stat.ModTime()
		}
	}

	if mostRecent == "" {
		return "none found", "0"
	}

	stat, err := os.Stat(mostRecent)
	if err != nil {
		return "none found", "0"
	}

	lastTime = stat.ModTime().Format("2006-01-02 15:04:05")
	size = formatSize(uint64(stat.Size()))

	return
}

func getRecentBackupFiles(dir string, limit int) []string {
	var files []string

	patterns := []string{
		"-name", "*.sql",
		"-o", "-name", "*.sql.gz",
		"-o", "-name", "*.dump",
		"-o", "-name", "backup*.tar.gz",
		"-o", "-name", "backup*.tar",
	}

	args := append([]string{dir, "-type", "f"}, patterns...)
	args = append(args, "-mtime", "-30")
	
	out, err := exec.Command("find", args...).Output()
	if err != nil {
		return files
	}

	allFiles := strings.Split(strings.TrimSpace(string(out)), "\n")

	// Get file mod times and sort
	type fileTime struct {
		path string
		time time.Time
	}

	var fileTimes []fileTime

	for _, file := range allFiles {
		if file == "" {
			continue
		}

		stat, err := os.Stat(file)
		if err != nil {
			continue
		}

		fileTimes = append(fileTimes, fileTime{
			path: file,
			time: stat.ModTime(),
		})
	}

	// Simple sort by time
	for i := 0; i < len(fileTimes)-1; i++ {
		for j := i + 1; j < len(fileTimes); j++ {
			if fileTimes[j].time.After(fileTimes[i].time) {
				fileTimes[i], fileTimes[j] = fileTimes[j], fileTimes[i]
			}
		}
	}

	// Take top N
	for i := 0; i < limit && i < len(fileTimes); i++ {
		files = append(files, fileTimes[i].path)
	}

	return files
}

func formatSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return "0MB"
	}

	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB"}
	if exp >= len(units) {
		exp = len(units) - 1
	}

	return formatFloat(float64(bytes)/float64(div)) + units[exp]
}

func formatFloat(f float64) string {
	s := ""
	if f < 10 {
		s = "%.1f"
	} else {
		s = "%.0f"
	}

	return strings.TrimSuffix(strings.TrimSuffix(sprintf(s, f), "0"), ".")
}

func sprintf(format string, a ...interface{}) string {
	// Minimal sprintf implementation for size formatting
	if format == "%.1f" && len(a) > 0 {
		if f, ok := a[0].(float64); ok {
			return strconv.FormatFloat(f, 'f', 1, 64)
		}
	}
	if format == "%.0f" && len(a) > 0 {
		if f, ok := a[0].(float64); ok {
			return strconv.FormatFloat(f, 'f', 0, 64)
		}
	}
	return ""
}
