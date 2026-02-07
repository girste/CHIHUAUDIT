package alerting

import (
	"encoding/json"
	"fmt"
)

// Change represents a detected difference between two audits.
type Change struct {
	Key         string `json:"key"`
	Description string `json:"description"`
	OldValue    any    `json:"old_value"`
	NewValue    any    `json:"new_value"`
}

// Config holds per-host alerting thresholds and ignore list.
type Config struct {
	WebhookURL      string
	CPUThreshold    float64
	MemoryThreshold float64
	DiskThreshold   float64
	IgnoreChanges   []string
}

func (c *Config) shouldIgnore(key string) bool {
	for _, k := range c.IgnoreChanges {
		if k == key {
			return true
		}
	}
	return false
}

// Compare detects critical changes between previous and current audit JSON results.
func Compare(prevRaw, currRaw json.RawMessage, cfg *Config) []Change {
	if prevRaw == nil || len(prevRaw) == 0 {
		return nil
	}

	var prev, curr map[string]any
	if err := json.Unmarshal(prevRaw, &prev); err != nil {
		return nil
	}
	if err := json.Unmarshal(currRaw, &curr); err != nil {
		return nil
	}

	var changes []Change

	// Firewall status
	if !cfg.shouldIgnore("firewall") {
		oldFw := getString(prev, "security", "firewall")
		newFw := getString(curr, "security", "firewall")
		if oldFw != "" && newFw != "" && oldFw != newFw {
			changes = append(changes, Change{
				Key:         "firewall",
				Description: fmt.Sprintf("Firewall status changed: %s → %s", oldFw, newFw),
				OldValue:    oldFw,
				NewValue:    newFw,
			})
		}
	}

	// Failed logins (+10 threshold)
	if !cfg.shouldIgnore("failed_logins") {
		oldFL := getFloat(prev, "security", "failed_logins")
		newFL := getFloat(curr, "security", "failed_logins")
		if newFL > oldFL+10 {
			changes = append(changes, Change{
				Key:         "failed_logins",
				Description: fmt.Sprintf("Failed logins increased: %.0f → %.0f", oldFL, newFL),
				OldValue:    oldFL,
				NewValue:    newFL,
			})
		}
	}

	// Failed services count
	if !cfg.shouldIgnore("failed_services") {
		oldFS := getFloat(prev, "services", "failed")
		newFS := getFloat(curr, "services", "failed")
		if oldFS != newFS {
			changes = append(changes, Change{
				Key:         "failed_services",
				Description: fmt.Sprintf("Failed services: %.0f → %.0f", oldFS, newFS),
				OldValue:    oldFS,
				NewValue:    newFS,
			})
		}
	}

	// Web server status
	if !cfg.shouldIgnore("web_server") {
		oldWS := getString(prev, "services", "web_status")
		newWS := getString(curr, "services", "web_status")
		if oldWS != "" && newWS != "" && oldWS != newWS {
			changes = append(changes, Change{
				Key:         "web_server",
				Description: fmt.Sprintf("Web server status: %s → %s", oldWS, newWS),
				OldValue:    oldWS,
				NewValue:    newWS,
			})
		}
	}

	// Database status
	if !cfg.shouldIgnore("database") {
		oldDB := getString(prev, "database", "db_status")
		newDB := getString(curr, "database", "db_status")
		if oldDB != "" && newDB != "" && oldDB != newDB {
			changes = append(changes, Change{
				Key:         "database",
				Description: fmt.Sprintf("Database status: %s → %s", oldDB, newDB),
				OldValue:    oldDB,
				NewValue:    newDB,
			})
		}
	}

	// CPU cross-threshold
	if !cfg.shouldIgnore("cpu_usage") {
		oldCPU := getFloat(prev, "resources", "cpu_percent")
		newCPU := getFloat(curr, "resources", "cpu_percent")
		if oldCPU <= cfg.CPUThreshold && newCPU > cfg.CPUThreshold {
			changes = append(changes, Change{
				Key:         "cpu_usage",
				Description: fmt.Sprintf("CPU above threshold: %.1f%% (threshold: %.0f%%)", newCPU, cfg.CPUThreshold),
				OldValue:    oldCPU,
				NewValue:    newCPU,
			})
		}
	}

	// Memory cross-threshold
	if !cfg.shouldIgnore("memory_usage") {
		oldMem := getFloat(prev, "resources", "mem_percent")
		newMem := getFloat(curr, "resources", "mem_percent")
		if oldMem <= cfg.MemoryThreshold && newMem > cfg.MemoryThreshold {
			changes = append(changes, Change{
				Key:         "memory_usage",
				Description: fmt.Sprintf("Memory above threshold: %.1f%% (threshold: %.0f%%)", newMem, cfg.MemoryThreshold),
				OldValue:    oldMem,
				NewValue:    newMem,
			})
		}
	}

	// Disk cross-threshold (check disk_mounts array)
	if !cfg.shouldIgnore("disk_usage") {
		compareDiskMounts(prev, curr, cfg.DiskThreshold, &changes)
	}

	// Docker containers decreased
	if !cfg.shouldIgnore("docker_containers") {
		prevDocker := getMap(prev, "docker")
		currDocker := getMap(curr, "docker")
		if getBool(prevDocker, "available") && getBool(currDocker, "available") {
			oldRunning := getFloatDirect(prevDocker, "running")
			newRunning := getFloatDirect(currDocker, "running")
			if oldRunning > newRunning {
				changes = append(changes, Change{
					Key:         "docker_containers",
					Description: fmt.Sprintf("Docker containers stopped: %.0f → %.0f running", oldRunning, newRunning),
					OldValue:    oldRunning,
					NewValue:    newRunning,
				})
			}
		}
	}

	// Disk health degraded
	if !cfg.shouldIgnore("disk_health") {
		oldDH := getString(prev, "storage", "disk_health")
		newDH := getString(curr, "storage", "disk_health")
		if oldDH != newDH && newDH != "all PASSED" && newDH != "" {
			changes = append(changes, Change{
				Key:         "disk_health",
				Description: fmt.Sprintf("Disk health changed: %s → %s", oldDH, newDH),
				OldValue:    oldDH,
				NewValue:    newDH,
			})
		}
	}

	// fail2ban status
	if !cfg.shouldIgnore("fail2ban") {
		oldF2B := getString(prev, "security", "fail2ban_status")
		newF2B := getString(curr, "security", "fail2ban_status")
		if oldF2B != "" && newF2B != "" && oldF2B != newF2B {
			changes = append(changes, Change{
				Key:         "fail2ban",
				Description: fmt.Sprintf("Fail2ban status changed: %s → %s", oldF2B, newF2B),
				OldValue:    oldF2B,
				NewValue:    newF2B,
			})
		}
	}

	// SSH port changed
	if !cfg.shouldIgnore("ssh_port") {
		oldPort := getFloat(prev, "security", "ssh_port")
		newPort := getFloat(curr, "security", "ssh_port")
		if oldPort > 0 && newPort > 0 && oldPort != newPort {
			changes = append(changes, Change{
				Key:         "ssh_port",
				Description: fmt.Sprintf("SSH port changed: %.0f → %.0f", oldPort, newPort),
				OldValue:    oldPort,
				NewValue:    newPort,
			})
		}
	}

	// SSH password auth
	if !cfg.shouldIgnore("ssh_password_auth") {
		oldAuth := getString(prev, "security", "ssh_password_auth")
		newAuth := getString(curr, "security", "ssh_password_auth")
		if oldAuth != "" && newAuth != "" && oldAuth != newAuth {
			changes = append(changes, Change{
				Key:         "ssh_password_auth",
				Description: fmt.Sprintf("SSH password auth changed: %s → %s", oldAuth, newAuth),
				OldValue:    oldAuth,
				NewValue:    newAuth,
			})
		}
	}

	// SSH root login
	if !cfg.shouldIgnore("ssh_root_login") {
		oldRoot := getString(prev, "security", "ssh_root_login")
		newRoot := getString(curr, "security", "ssh_root_login")
		if oldRoot != "" && newRoot != "" && oldRoot != newRoot {
			changes = append(changes, Change{
				Key:         "ssh_root_login",
				Description: fmt.Sprintf("SSH root login changed: %s → %s", oldRoot, newRoot),
				OldValue:    oldRoot,
				NewValue:    newRoot,
			})
		}
	}

	// SUID binaries increased
	if !cfg.shouldIgnore("suid_binaries") {
		oldSUID := getFloat(prev, "security", "suid_count")
		newSUID := getFloat(curr, "security", "suid_count")
		if newSUID > oldSUID && oldSUID > 0 {
			changes = append(changes, Change{
				Key:         "suid_binaries",
				Description: fmt.Sprintf("SUID binaries increased: %.0f → %.0f", oldSUID, newSUID),
				OldValue:    oldSUID,
				NewValue:    newSUID,
			})
		}
	}

	// SSL certificates expiring
	if !cfg.shouldIgnore("ssl_expiring") {
		oldExpiring := getFloat(prev, "security", "ssl_expiring_soon")
		newExpiring := getFloat(curr, "security", "ssl_expiring_soon")
		if newExpiring > 0 && newExpiring != oldExpiring {
			changes = append(changes, Change{
				Key:         "ssl_expiring",
				Description: fmt.Sprintf("SSL certificates expiring soon: %.0f", newExpiring),
				OldValue:    oldExpiring,
				NewValue:    newExpiring,
			})
		}
	}

	// Security updates
	if !cfg.shouldIgnore("security_updates") {
		oldUpdates := getFloat(prev, "system", "security_updates")
		newUpdates := getFloat(curr, "system", "security_updates")
		if newUpdates > oldUpdates && oldUpdates >= 0 {
			changes = append(changes, Change{
				Key:         "security_updates",
				Description: fmt.Sprintf("Security updates available: %.0f → %.0f", oldUpdates, newUpdates),
				OldValue:    oldUpdates,
				NewValue:    newUpdates,
			})
		}
	}

	return changes
}

func compareDiskMounts(prev, curr map[string]any, threshold float64, changes *[]Change) {
	prevMounts := getArray(prev, "resources", "disk_mounts")
	currMounts := getArray(curr, "resources", "disk_mounts")

	for _, cm := range currMounts {
		currMount, ok := cm.(map[string]any)
		if !ok {
			continue
		}
		currPath, _ := currMount["path"].(string)
		if currPath == "" {
			continue
		}
		currPct, _ := currMount["percent"].(float64)

		for _, pm := range prevMounts {
			prevMount, ok := pm.(map[string]any)
			if !ok {
				continue
			}
			prevPath, _ := prevMount["path"].(string)
			if prevPath != currPath {
				continue
			}
			prevPct, _ := prevMount["percent"].(float64)

			if prevPct <= threshold && currPct > threshold {
				*changes = append(*changes, Change{
					Key:         "disk_usage",
					Description: fmt.Sprintf("Disk %s above threshold: %.1f%% (threshold: %.0f%%)", currPath, currPct, threshold),
					OldValue:    prevPct,
					NewValue:    currPct,
				})
			}
			break
		}
	}
}

// JSON navigation helpers

func getMap(m map[string]any, keys ...string) map[string]any {
	cur := m
	for _, k := range keys {
		v, ok := cur[k]
		if !ok {
			return nil
		}
		cur, ok = v.(map[string]any)
		if !ok {
			return nil
		}
	}
	return cur
}

func getString(m map[string]any, keys ...string) string {
	if len(keys) < 1 {
		return ""
	}
	sub := getMap(m, keys[:len(keys)-1]...)
	if sub == nil {
		return ""
	}
	s, _ := sub[keys[len(keys)-1]].(string)
	return s
}

func getFloat(m map[string]any, keys ...string) float64 {
	if len(keys) < 1 {
		return 0
	}
	sub := getMap(m, keys[:len(keys)-1]...)
	if sub == nil {
		return 0
	}
	f, _ := sub[keys[len(keys)-1]].(float64)
	return f
}

func getFloatDirect(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	f, _ := m[key].(float64)
	return f
}

func getBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

func getArray(m map[string]any, keys ...string) []any {
	if len(keys) < 1 {
		return nil
	}
	sub := getMap(m, keys[:len(keys)-1]...)
	if sub == nil {
		return nil
	}
	a, _ := sub[keys[len(keys)-1]].([]any)
	return a
}

// MetricValue holds a named metric extracted from audit data.
type MetricValue struct {
	Name  string
	Value float64
}

// ExtractMetricValues extracts cpu_percent, mem_percent, and disk mount percentages
// from raw audit JSON for threshold breach tracking.
func ExtractMetricValues(currRaw json.RawMessage) []MetricValue {
	var curr map[string]any
	if err := json.Unmarshal(currRaw, &curr); err != nil {
		return nil
	}

	var metrics []MetricValue

	if cpu := getFloat(curr, "resources", "cpu_percent"); cpu > 0 {
		metrics = append(metrics, MetricValue{Name: "cpu_percent", Value: cpu})
	}
	if mem := getFloat(curr, "resources", "mem_percent"); mem > 0 {
		metrics = append(metrics, MetricValue{Name: "mem_percent", Value: mem})
	}

	diskMounts := getArray(curr, "resources", "disk_mounts")
	for _, dm := range diskMounts {
		mount, ok := dm.(map[string]any)
		if !ok {
			continue
		}
		path, _ := mount["path"].(string)
		pct, _ := mount["percent"].(float64)
		if path != "" && pct > 0 {
			metrics = append(metrics, MetricValue{
				Name:  fmt.Sprintf("disk:%s", path),
				Value: pct,
			})
		}
	}

	return metrics
}
