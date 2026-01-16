package monitoring

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"
)

// MonitoringManager manages the monitoring daemon lifecycle
type MonitoringManager struct {
	logDir  string
	pidFile string
}

// NewMonitoringManager creates a new manager
func NewMonitoringManager(logDir string) *MonitoringManager {
	return &MonitoringManager{
		logDir:  logDir,
		pidFile: filepath.Join(logDir, "monitoring.pid"),
	}
}

// Status represents monitoring daemon status
type Status struct {
	Running          bool   `json:"running"`
	PID              int    `json:"pid,omitempty"`
	LogDir           string `json:"log_dir"`
	BaselineExists   bool   `json:"baseline_exists"`
	BulletinCount    int    `json:"bulletin_count"`
	AnomalyCount     int    `json:"anomaly_count"`
	TotalDiskUsageKB int64  `json:"total_disk_usage_kb"`
}

// StartResult represents the result of starting monitoring
type StartResult struct {
	Success         bool   `json:"success"`
	Error           string `json:"error,omitempty"`
	PID             int    `json:"pid,omitempty"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
	LogDir          string `json:"log_dir,omitempty"`
}

// StopResult represents the result of stopping monitoring
type StopResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

// CleanupResult represents the result of cleaning up old logs
type CleanupResult struct {
	BulletinsRemoved   int `json:"bulletins_removed"`
	AnomaliesRemoved   int `json:"anomalies_removed"`
	BulletinsRemaining int `json:"bulletins_remaining"`
	AnomaliesRemaining int `json:"anomalies_remaining"`
}

// IsRunning checks if the monitoring daemon is running
func (m *MonitoringManager) IsRunning() bool {
	data, err := os.ReadFile(m.pidFile)
	if err != nil {
		return false
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		_ = os.Remove(m.pidFile)
		return false
	}

	// Check if process exists
	process, err := os.FindProcess(pid)
	if err != nil {
		_ = os.Remove(m.pidFile)
		return false
	}

	// On Unix, FindProcess always succeeds. Check if process is really running.
	err = process.Signal(syscall.Signal(0))
	if err != nil {
		_ = os.Remove(m.pidFile)
		return false
	}

	return true
}

// GetStatus returns detailed monitoring status
func (m *MonitoringManager) GetStatus() *Status {
	status := &Status{
		Running: m.IsRunning(),
		LogDir:  m.logDir,
	}

	// Get PID if running
	if status.Running {
		if data, err := os.ReadFile(m.pidFile); err == nil {
			if pid, err := strconv.Atoi(string(data)); err == nil {
				status.PID = pid
			}
		}
	}

	// Check baseline exists
	baselinePath := filepath.Join(m.logDir, "baseline.json")
	if _, err := os.Stat(baselinePath); err == nil {
		status.BaselineExists = true
	}

	// Count log files
	if entries, err := os.ReadDir(m.logDir); err == nil {
		var totalSize int64
		for _, entry := range entries {
			if !entry.IsDir() {
				name := entry.Name()
				if len(name) > 9 && name[:9] == "bulletin_" {
					status.BulletinCount++
				} else if len(name) > 8 && name[:8] == "anomaly_" {
					status.AnomalyCount++
				}
				if info, err := entry.Info(); err == nil {
					totalSize += info.Size()
				}
			}
		}
		status.TotalDiskUsageKB = totalSize / 1024
	}

	return status
}

// Start starts the monitoring daemon in background
func (m *MonitoringManager) Start(intervalSeconds int) *StartResult {
	if m.IsRunning() {
		return &StartResult{
			Success: false,
			Error:   "Monitoring is already running",
		}
	}

	// Ensure log directory exists
	if err := os.MkdirAll(m.logDir, 0700); err != nil {
		return &StartResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to create log directory: %v", err),
		}
	}

	// Find the executable path
	execPath, err := os.Executable()
	if err != nil {
		return &StartResult{
			Success: false,
			Error:   fmt.Sprintf("Cannot find executable: %v", err),
		}
	}

	// Start daemon in background
	cmd := exec.Command(execPath, "monitor",
		"--interval", strconv.Itoa(intervalSeconds),
		"--log-dir", m.logDir)

	// Detach from parent
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		return &StartResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to start daemon: %v", err),
		}
	}

	// Wait a moment for process to start
	time.Sleep(time.Second)

	// Check if still running
	if cmd.Process == nil {
		return &StartResult{
			Success: false,
			Error:   "Daemon process terminated immediately after start",
		}
	}

	// Save PID
	pidStr := strconv.Itoa(cmd.Process.Pid)
	if err := os.WriteFile(m.pidFile, []byte(pidStr), 0600); err != nil {
		return &StartResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to write PID file: %v", err),
		}
	}

	return &StartResult{
		Success:         true,
		PID:             cmd.Process.Pid,
		IntervalSeconds: intervalSeconds,
		LogDir:          m.logDir,
	}
}

// Stop stops the monitoring daemon
func (m *MonitoringManager) Stop() *StopResult {
	if !m.IsRunning() {
		return &StopResult{
			Success: false,
			Error:   "Monitoring is not running",
		}
	}

	data, err := os.ReadFile(m.pidFile)
	if err != nil {
		return &StopResult{
			Success: false,
			Error:   fmt.Sprintf("Cannot read PID file: %v", err),
		}
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return &StopResult{
			Success: false,
			Error:   fmt.Sprintf("Invalid PID in file: %v", err),
		}
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return &StopResult{
			Success: false,
			Error:   fmt.Sprintf("Cannot find process: %v", err),
		}
	}

	// Send SIGTERM for graceful shutdown
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return &StopResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to send signal: %v", err),
		}
	}

	// Wait up to 5 seconds for process to stop
	for i := 0; i < 50; i++ {
		if err := process.Signal(syscall.Signal(0)); err != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Remove PID file
	os.Remove(m.pidFile)

	return &StopResult{
		Success: true,
		Message: "Monitoring stopped",
	}
}

// CleanupOldLogs removes old log files to prevent disk fill
func (m *MonitoringManager) CleanupOldLogs(maxBulletins, maxAnomalies int) *CleanupResult {
	result := &CleanupResult{}

	entries, err := os.ReadDir(m.logDir)
	if err != nil {
		return result
	}

	// Collect and sort files by modification time
	type fileInfo struct {
		path    string
		modTime time.Time
	}

	var bulletins, anomalies []fileInfo

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		path := filepath.Join(m.logDir, name)

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if len(name) > 9 && name[:9] == "bulletin_" {
			bulletins = append(bulletins, fileInfo{path: path, modTime: info.ModTime()})
		} else if len(name) > 8 && name[:8] == "anomaly_" {
			anomalies = append(anomalies, fileInfo{path: path, modTime: info.ModTime()})
		}
	}

	// Sort by modification time (oldest first)
	sort.Slice(bulletins, func(i, j int) bool {
		return bulletins[i].modTime.Before(bulletins[j].modTime)
	})
	sort.Slice(anomalies, func(i, j int) bool {
		return anomalies[i].modTime.Before(anomalies[j].modTime)
	})

	// Remove old bulletins
	if len(bulletins) > maxBulletins {
		toRemove := bulletins[:len(bulletins)-maxBulletins]
		for _, f := range toRemove {
			if os.Remove(f.path) == nil {
				result.BulletinsRemoved++
			}
		}
	}
	result.BulletinsRemaining = len(bulletins) - result.BulletinsRemoved

	// Remove old anomalies
	if len(anomalies) > maxAnomalies {
		toRemove := anomalies[:len(anomalies)-maxAnomalies]
		for _, f := range toRemove {
			if os.Remove(f.path) == nil {
				result.AnomaliesRemoved++
			}
		}
	}
	result.AnomaliesRemaining = len(anomalies) - result.AnomaliesRemoved

	return result
}

// GetLogDir returns the log directory path
func (m *MonitoringManager) GetLogDir() string {
	return m.logDir
}
