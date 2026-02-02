package monitoring

import (
	"context"
	"os/exec"
	"strconv"
	"strings"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
)

// SystemHealth represents critical system metrics
type SystemHealth struct {
	ServicesDown   []ServiceStatus `json:"services_down,omitempty"`
	DiskCritical   []DiskStatus    `json:"disk_critical,omitempty"`
	MemoryPressure bool            `json:"memory_pressure"`
	MemoryUsedPct  float64         `json:"memory_used_pct"`
	SwapUsedPct    float64         `json:"swap_used_pct"`
	LoadAverage    []float64       `json:"load_average"`
	OOMKills       int             `json:"oom_kills"`
	FailedServices []string        `json:"failed_services,omitempty"`
	JournalErrors  int             `json:"journal_errors"`
	UptimeSeconds  int64           `json:"uptime_seconds"`
}

// ServiceStatus represents the status of a critical service
type ServiceStatus struct {
	Name    string `json:"name"`
	Active  bool   `json:"active"`
	Enabled bool   `json:"enabled"`
	PID     int    `json:"pid,omitempty"`
}

// DiskStatus represents disk usage information
type DiskStatus struct {
	Mountpoint string  `json:"mountpoint"`
	UsedPct    float64 `json:"used_pct"`
	Available  string  `json:"available"`
	Filesystem string  `json:"filesystem"`
}

// CheckSystemHealth performs critical system health checks
func CheckSystemHealth(ctx context.Context, cfg *config.Config) *SystemHealth {
	health := &SystemHealth{
		LoadAverage: []float64{0, 0, 0},
	}

	// Check critical services (auto-detect what's installed)
	health.ServicesDown = checkCriticalServices(ctx)

	// Check disk usage
	health.DiskCritical = checkDiskUsage(ctx, cfg)

	// Check memory
	health.MemoryUsedPct, health.SwapUsedPct, health.MemoryPressure = checkMemory(ctx, cfg)

	// Check load average
	health.LoadAverage = checkLoadAverage(ctx)

	// Check for OOM kills in recent journal
	health.OOMKills = checkOOMKills(ctx)

	// Check failed systemd services
	health.FailedServices = checkFailedServices(ctx)

	// Count recent journal errors
	health.JournalErrors = checkJournalErrors(ctx)

	// Get system uptime
	health.UptimeSeconds = getUptime(ctx)

	return health
}

// checkCriticalServices checks status of commonly installed services
func checkCriticalServices(ctx context.Context) []ServiceStatus {
	// Auto-detect which services are installed and should be running
	candidateServices := []string{
		"nginx", "apache2", "httpd", "caddy",
		"postgresql", "mysql", "mariadb",
		"redis", "redis-server",
		"docker", "containerd",
		"mongod", "mongodb",
	}

	var downServices []ServiceStatus

	for _, svc := range candidateServices {
		// Check if service exists (is installed)
		checkCmd := exec.CommandContext(ctx, "systemctl", "cat", svc)
		if err := checkCmd.Run(); err != nil {
			continue // Service not installed, skip
		}

		// Service exists, check if it's supposed to be running
		statusCmd := exec.CommandContext(ctx, "systemctl", "is-active", svc)
		output, _ := statusCmd.Output()
		active := strings.TrimSpace(string(output)) == "active"

		enabledCmd := exec.CommandContext(ctx, "systemctl", "is-enabled", svc)
		enabledOutput, _ := enabledCmd.Output()
		enabled := strings.TrimSpace(string(enabledOutput)) == "enabled"

		// If service is enabled but not active → problem
		if enabled && !active {
			downServices = append(downServices, ServiceStatus{
				Name:    svc,
				Active:  active,
				Enabled: enabled,
			})
		}
	}

	return downServices
}

// checkDiskUsage checks for critically full disks (configurable threshold, default >90%)
func checkDiskUsage(ctx context.Context, cfg *config.Config) []DiskStatus {
	var critical []DiskStatus

	// Get threshold from config, default 90%
	threshold := 90.0
	if cfg.Whitelist != nil {
		threshold = cfg.Whitelist.GetDiskThreshold()
	}

	result, _ := system.RunCommand(ctx, system.TimeoutShort, "df", "-h", "--output=target,pcent,avail,source")
	if result == nil || !result.Success {
		return critical
	}

	lines := strings.Split(result.Stdout, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		mountpoint := fields[0]
		usedPctStr := strings.TrimSuffix(fields[1], "%")
		available := fields[2]
		filesystem := fields[3]

		usedPct, err := strconv.ParseFloat(usedPctStr, 64)
		if err != nil {
			continue
		}

		// Critical if above threshold
		if usedPct > threshold {
			critical = append(critical, DiskStatus{
				Mountpoint: mountpoint,
				UsedPct:    usedPct,
				Available:  available,
				Filesystem: filesystem,
			})
		}
	}

	return critical
}

// checkMemory checks memory and swap usage (configurable thresholds)
func checkMemory(ctx context.Context, cfg *config.Config) (memPct, swapPct float64, pressure bool) {
	result, _ := system.RunCommand(ctx, system.TimeoutShort, "free", "-m")
	if result == nil || !result.Success {
		return 0, 0, false
	}

	// Get thresholds from config, defaults 90% RAM, 10% swap
	ramThreshold := 90.0
	swapThreshold := 10.0
	if cfg.Whitelist != nil {
		ramThreshold = cfg.Whitelist.GetRAMThreshold()
		swapThreshold = cfg.Whitelist.GetSwapThreshold()
	}

	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		if fields[0] == "Mem:" && len(fields) >= 3 {
			total, _ := strconv.ParseFloat(fields[1], 64)
			used, _ := strconv.ParseFloat(fields[2], 64)
			if total > 0 {
				memPct = (used / total) * 100
			}
		} else if fields[0] == "Swap:" && len(fields) >= 3 {
			total, _ := strconv.ParseFloat(fields[1], 64)
			used, _ := strconv.ParseFloat(fields[2], 64)
			if total > 0 {
				swapPct = (used / total) * 100
			}
		}
	}

	// Memory pressure if above configured thresholds
	pressure = memPct > ramThreshold || swapPct > swapThreshold

	return memPct, swapPct, pressure
}

// checkLoadAverage gets 1, 5, 15 minute load averages
func checkLoadAverage(ctx context.Context) []float64 {
	result, _ := system.RunCommand(ctx, system.TimeoutShort, "uptime")
	if result == nil || !result.Success {
		return []float64{0, 0, 0}
	}

	// Parse "load average: 0.52, 0.58, 0.59"
	if idx := strings.Index(result.Stdout, "load average:"); idx != -1 {
		loadStr := result.Stdout[idx+13:]
		loadStr = strings.TrimSpace(loadStr)
		parts := strings.Split(loadStr, ",")

		loads := []float64{0, 0, 0}
		for i, part := range parts {
			if i >= 3 {
				break
			}
			val, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
			if err == nil {
				loads[i] = val
			}
		}
		return loads
	}

	return []float64{0, 0, 0}
}

// checkOOMKills checks for recent out-of-memory kills
func checkOOMKills(ctx context.Context) int {
	// Check journal for OOM kills in last 5 minutes
	result, _ := system.RunCommand(ctx, system.TimeoutMedium, "journalctl", "--since", "5 minutes ago", "-p", "warning", "--no-pager")
	if result == nil || !result.Success {
		return 0
	}

	count := strings.Count(result.Stdout, "Out of memory")
	count += strings.Count(result.Stdout, "OOM killer")
	return count
}

// checkFailedServices gets list of failed systemd services
func checkFailedServices(ctx context.Context) []string {
	result, _ := system.RunCommand(ctx, system.TimeoutShort, "systemctl", "list-units", "--state=failed", "--no-pager", "--no-legend")
	if result == nil || !result.Success {
		return nil
	}

	var failed []string
	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			failed = append(failed, fields[0])
		}
	}

	return failed
}

// checkJournalErrors counts ERROR level messages in last 5 minutes
func checkJournalErrors(ctx context.Context) int {
	result, _ := system.RunCommand(ctx, system.TimeoutMedium, "journalctl", "--since", "5 minutes ago", "-p", "err", "--no-pager")
	if result == nil || !result.Success {
		return 0
	}

	// Count non-empty lines
	count := 0
	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "--") {
			count++
		}
	}

	return count
}

// getUptime returns system uptime in seconds
func getUptime(ctx context.Context) int64 {
	result, _ := system.RunCommand(ctx, system.TimeoutShort, "cat", "/proc/uptime")
	if result == nil || !result.Success {
		return 0
	}

	fields := strings.Fields(result.Stdout)
	if len(fields) > 0 {
		uptime, _ := strconv.ParseFloat(fields[0], 64)
		return int64(uptime)
	}

	return 0
}

// detectSystemHealthAnomalies converts system health issues to anomalies
func detectSystemHealthAnomalies(health *SystemHealth) []Anomaly {
	var anomalies []Anomaly

	// Critical: Services down
	for _, svc := range health.ServicesDown {
		anomalies = append(anomalies, Anomaly{
			Severity: SeverityCritical,
			Category: "service",
			Message:  "Critical service is down: " + svc.Name,
			Details: map[string]interface{}{
				"service": svc.Name,
				"enabled": svc.Enabled,
				"active":  svc.Active,
			},
		})
	}

	// Critical: Disk full
	for _, disk := range health.DiskCritical {
		anomalies = append(anomalies, Anomaly{
			Severity: SeverityCritical,
			Category: "disk",
			Message:  "Disk critically full: " + disk.Mountpoint + " (" + strconv.FormatFloat(disk.UsedPct, 'f', 1, 64) + "%)",
			Details: map[string]interface{}{
				"mountpoint": disk.Mountpoint,
				"used_pct":   disk.UsedPct,
				"available":  disk.Available,
			},
		})
	}

	// Critical: OOM kills
	if health.OOMKills > 0 {
		anomalies = append(anomalies, Anomaly{
			Severity: SeverityCritical,
			Category: "memory",
			Message:  "Out of memory kills detected: " + strconv.Itoa(health.OOMKills) + " processes killed",
			Details: map[string]interface{}{
				"oom_kills":       health.OOMKills,
				"memory_used":     health.MemoryUsedPct,
				"swap_used":       health.SwapUsedPct,
				"memory_pressure": health.MemoryPressure,
			},
		})
	}

	// High: Memory pressure
	if health.MemoryPressure && health.OOMKills == 0 {
		anomalies = append(anomalies, Anomaly{
			Severity: SeverityHigh,
			Category: "memory",
			Message:  "Memory pressure detected (RAM: " + strconv.FormatFloat(health.MemoryUsedPct, 'f', 1, 64) + "%, Swap: " + strconv.FormatFloat(health.SwapUsedPct, 'f', 1, 64) + "%)",
			Details: map[string]interface{}{
				"memory_used": health.MemoryUsedPct,
				"swap_used":   health.SwapUsedPct,
			},
		})
	}

	// High: Failed services
	if len(health.FailedServices) > 0 {
		anomalies = append(anomalies, Anomaly{
			Severity: SeverityHigh,
			Category: "service",
			Message:  "Failed systemd services detected: " + strings.Join(health.FailedServices, ", "),
			Details: map[string]interface{}{
				"failed_services": health.FailedServices,
				"count":           len(health.FailedServices),
			},
		})
	}

	// Medium: High error rate in journal
	if health.JournalErrors > 10 {
		anomalies = append(anomalies, Anomaly{
			Severity: SeverityMedium,
			Category: "system",
			Message:  "High error rate in system journal: " + strconv.Itoa(health.JournalErrors) + " errors in last 5 minutes",
			Details: map[string]interface{}{
				"error_count": health.JournalErrors,
				"period":      "5 minutes",
			},
		})
	}

	return anomalies
}
