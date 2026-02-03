package analyzers

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
)

// PerformanceAnalyzer checks CPU, RAM, and disk usage against configurable thresholds.
// Thresholds are set via whitelist config (thresholds section); defaults are safe
// values that work without any config file.
type PerformanceAnalyzer struct{}

func (a *PerformanceAnalyzer) Name() string           { return "performance" }
func (a *PerformanceAnalyzer) RequiresSudo() bool     { return false }
func (a *PerformanceAnalyzer) Timeout() time.Duration { return system.TimeoutShort }

func (a *PerformanceAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	// Resolve thresholds — whitelist overrides, safe defaults otherwise
	cpuThreshold := float64(runtime.NumCPU()) * 1.5
	ramThreshold := 90.0
	diskThreshold := 90.0
	if cfg.Whitelist != nil {
		ramThreshold = cfg.Whitelist.GetRAMThreshold()
		diskThreshold = cfg.Whitelist.GetDiskThreshold()
		if t := cfg.Whitelist.GetCPUThreshold(); t > 0 {
			cpuThreshold = t
		}
	}

	// --- CPU load (1 / 5 / 15 min) from /proc/loadavg ---
	var loadAvg [3]float64
	if cpuRes, _ := system.RunCommand(ctx, system.TimeoutShort, "cat", "/proc/loadavg"); cpuRes != nil && cpuRes.Success {
		for i, f := range strings.Fields(cpuRes.Stdout) {
			if i >= 3 {
				break
			}
			loadAvg[i], _ = strconv.ParseFloat(f, 64)
		}
	}

	// --- RAM / Swap from free -m ---
	var ramUsedPct, swapUsedPct float64
	if freeRes, _ := system.RunCommand(ctx, system.TimeoutShort, "free", "-m"); freeRes != nil && freeRes.Success {
		for _, line := range strings.Split(freeRes.Stdout, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			total, _ := strconv.ParseFloat(fields[1], 64)
			used, _ := strconv.ParseFloat(fields[2], 64)
			if total == 0 {
				continue
			}
			switch fields[0] {
			case "Mem:":
				ramUsedPct = (used / total) * 100
			case "Swap:":
				swapUsedPct = (used / total) * 100
			}
		}
	}

	// --- Disk from df ---
	var disks []map[string]interface{}
	var criticalDisks []string
	if dfRes, _ := system.RunCommand(ctx, system.TimeoutShort, "df", "-h", "--output=target,pcent,avail"); dfRes != nil && dfRes.Success {
		for i, line := range strings.Split(dfRes.Stdout, "\n") {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue // skip header
			}
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			pct, err := strconv.ParseFloat(strings.TrimSuffix(fields[1], "%"), 64)
			if err != nil {
				continue
			}
			disks = append(disks, map[string]interface{}{
				"mountpoint": fields[0],
				"used_pct":   pct,
				"available":  fields[2],
			})
			if pct > diskThreshold {
				criticalDisks = append(criticalDisks, fields[0])
			}
		}
	}

	// --- Populate result data ---
	result.Data = map[string]interface{}{
		"cpu": map[string]interface{}{
			"load_1m":   loadAvg[0],
			"load_5m":   loadAvg[1],
			"load_15m":  loadAvg[2],
			"threshold": cpuThreshold,
		},
		"ram": map[string]interface{}{
			"used_pct":  ramUsedPct,
			"threshold": ramThreshold,
		},
		"swap": map[string]interface{}{
			"used_pct": swapUsedPct,
		},
		"disk": disks,
	}

	// --- Issues ---

	if loadAvg[0] > cpuThreshold {
		result.AddIssue(NewIssue(SeverityHigh,
			fmt.Sprintf("CPU load high: %.2f (threshold: %.2f)", loadAvg[0], cpuThreshold),
			"Investigate running processes"))
	}

	if ramUsedPct > ramThreshold {
		result.AddIssue(NewIssue(SeverityHigh,
			fmt.Sprintf("RAM usage at %.1f%% (threshold: %.0f%%)", ramUsedPct, ramThreshold),
			"Review memory-intensive processes"))
	}

	if swapUsedPct > 0 {
		sev := SeverityMedium
		if swapUsedPct > 50 {
			sev = SeverityHigh
		}
		result.AddIssue(NewIssue(sev,
			fmt.Sprintf("Swap in use: %.1f%%", swapUsedPct),
			"Consider increasing RAM or optimizing applications"))
	}

	for _, mount := range criticalDisks {
		result.AddIssue(NewIssue(SeverityHigh,
			fmt.Sprintf("Disk nearly full: %s (>%.0f%%)", mount, diskThreshold),
			"Free disk space or expand storage"))
	}

	return result, nil
}
