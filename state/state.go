package state

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"chihuaudit/checks"
	"chihuaudit/config"
)

type Change struct {
	Key          string
	Description  string
	OldValue     interface{}
	NewValue     interface{}
	ShouldNotify bool
}

const stateFile = "/var/lib/chihuaudit/state.json"
const stateFallback = "/tmp/chihuaudit.state.json"

// Compare checks for meaningful changes between two audit results
func Compare(previous, current *checks.AuditResults, cfg *config.Config) []Change {
	var changes []Change

	// Skip if no previous state
	if previous == nil {
		return changes
	}

	// Resources - with thresholds
	if change := compareCPU(previous.Resources, current.Resources, cfg); change != nil {
		changes = append(changes, *change)
	}

	if change := compareMemory(previous.Resources, current.Resources, cfg); change != nil {
		changes = append(changes, *change)
	}

	if change := compareDisk(previous.Resources, current.Resources, cfg); change != nil {
		changes = append(changes, *change)
	}

	// Security - critical changes
	if previous.Security.Firewall != current.Security.Firewall {
		changes = append(changes, Change{
			Key:          "firewall",
			Description:  fmt.Sprintf("Firewall status changed: %s → %s", previous.Security.Firewall, current.Security.Firewall),
			OldValue:     previous.Security.Firewall,
			NewValue:     current.Security.Firewall,
			ShouldNotify: !cfg.ShouldIgnore("firewall"),
		})
	}

	if previous.Security.FailedLogins != current.Security.FailedLogins {
		if current.Security.FailedLogins > previous.Security.FailedLogins+10 { // Threshold: +10 failures
			changes = append(changes, Change{
				Key:          "failed_logins",
				Description:  fmt.Sprintf("Failed logins increased: %d → %d", previous.Security.FailedLogins, current.Security.FailedLogins),
				OldValue:     previous.Security.FailedLogins,
				NewValue:     current.Security.FailedLogins,
				ShouldNotify: !cfg.ShouldIgnore("failed_logins"),
			})
		}
	}

	// Services - failures
	if previous.Services.Failed != current.Services.Failed {
		changes = append(changes, Change{
			Key:          "failed_services",
			Description:  fmt.Sprintf("Failed services: %d → %d", previous.Services.Failed, current.Services.Failed),
			OldValue:     previous.Services.Failed,
			NewValue:     current.Services.Failed,
			ShouldNotify: !cfg.ShouldIgnore("failed_services"),
		})
	}

	if previous.Services.WebStatus != current.Services.WebStatus {
		changes = append(changes, Change{
			Key:          "web_server",
			Description:  fmt.Sprintf("Web server status: %s → %s", previous.Services.WebStatus, current.Services.WebStatus),
			OldValue:     previous.Services.WebStatus,
			NewValue:     current.Services.WebStatus,
			ShouldNotify: !cfg.ShouldIgnore("web_server"),
		})
	}

	if previous.Services.DBStatus != current.Services.DBStatus {
		changes = append(changes, Change{
			Key:          "database",
			Description:  fmt.Sprintf("Database status: %s → %s", previous.Services.DBStatus, current.Services.DBStatus),
			OldValue:     previous.Services.DBStatus,
			NewValue:     current.Services.DBStatus,
			ShouldNotify: !cfg.ShouldIgnore("database"),
		})
	}

	// Docker - if stopped
	if previous.Docker.Available && current.Docker.Available {
		if previous.Docker.Running > current.Docker.Running {
			changes = append(changes, Change{
				Key:          "docker_containers",
				Description:  fmt.Sprintf("Docker containers stopped: %d → %d running", previous.Docker.Running, current.Docker.Running),
				OldValue:     previous.Docker.Running,
				NewValue:     current.Docker.Running,
				ShouldNotify: !cfg.ShouldIgnore("docker_containers"),
			})
		}
	}

	// Storage - disk health
	if previous.Storage.DiskHealth != current.Storage.DiskHealth {
		if current.Storage.DiskHealth != "all PASSED" {
			changes = append(changes, Change{
				Key:          "disk_health",
				Description:  fmt.Sprintf("Disk health changed: %s → %s", previous.Storage.DiskHealth, current.Storage.DiskHealth),
				OldValue:     previous.Storage.DiskHealth,
				NewValue:     current.Storage.DiskHealth,
				ShouldNotify: !cfg.ShouldIgnore("disk_health"),
			})
		}
	}

	return changes
}

func compareCPU(prev, curr checks.Resources, cfg *config.Config) *Change {
	threshold := cfg.NotificationFilters.CPUThreshold

	// Check if crossed threshold
	prevAbove := prev.CPUPercent > threshold
	currAbove := curr.CPUPercent > threshold

	if !prevAbove && currAbove {
		return &Change{
			Key:          "cpu_usage",
			Description:  fmt.Sprintf("CPU usage above threshold: %.1f%% (threshold: %.0f%%)", curr.CPUPercent, threshold),
			OldValue:     prev.CPUPercent,
			NewValue:     curr.CPUPercent,
			ShouldNotify: !cfg.ShouldIgnore("cpu_usage"),
		}
	}

	return nil
}

func compareMemory(prev, curr checks.Resources, cfg *config.Config) *Change {
	threshold := cfg.NotificationFilters.MemoryThreshold

	prevAbove := prev.MemPercent > threshold
	currAbove := curr.MemPercent > threshold

	if !prevAbove && currAbove {
		return &Change{
			Key:          "memory_usage",
			Description:  fmt.Sprintf("Memory usage above threshold: %.1f%% (threshold: %.0f%%)", curr.MemPercent, threshold),
			OldValue:     prev.MemPercent,
			NewValue:     curr.MemPercent,
			ShouldNotify: !cfg.ShouldIgnore("memory_usage"),
		}
	}

	return nil
}

func compareDisk(prev, curr checks.Resources, cfg *config.Config) *Change {
	threshold := cfg.NotificationFilters.DiskThreshold

	for _, currMount := range curr.DiskMounts {
		for _, prevMount := range prev.DiskMounts {
			if currMount.Path == prevMount.Path {
				prevAbove := prevMount.Percent > threshold
				currAbove := currMount.Percent > threshold

				if !prevAbove && currAbove {
					return &Change{
						Key:          "disk_usage",
						Description:  fmt.Sprintf("Disk %s above threshold: %.1f%% (threshold: %.0f%%)", currMount.Path, currMount.Percent, threshold),
						OldValue:     prevMount.Percent,
						NewValue:     currMount.Percent,
						ShouldNotify: !cfg.ShouldIgnore("disk_usage"),
					}
				}
			}
		}
	}

	return nil
}

// Log writes a change to the log file
func Log(change Change) {
	logPath := "/var/log/chihuaudit.log"

	// Try to create/open log file
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Fallback to tmp
		logPath = "/tmp/chihuaudit.log"
		f, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
	}
	defer func() { _ = f.Close() }()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] %s: %s\n", timestamp, change.Key, change.Description)
	_, _ = f.WriteString(logLine)
}

// Save persists the current audit results to disk
func Save(results *checks.AuditResults) error {
	data, err := json.Marshal(results)
	if err != nil {
		return err
	}

	// Try primary location first
	if err := os.MkdirAll("/var/lib/chihuaudit", 0755); err == nil {
		if err := os.WriteFile(stateFile, data, 0644); err == nil {
			return nil
		}
	}

	// Fallback to tmp
	return os.WriteFile(stateFallback, data, 0644)
}

// Load retrieves the last audit results from disk
func Load() *checks.AuditResults {
	var results checks.AuditResults

	// Try primary location
	data, err := os.ReadFile(stateFile)
	if err != nil {
		// Try fallback
		data, err = os.ReadFile(stateFallback)
		if err != nil {
			return nil
		}
	}

	if err := json.Unmarshal(data, &results); err != nil {
		return nil
	}

	return &results
}
