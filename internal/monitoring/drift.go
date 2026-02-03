package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/girste/chihuaudit/internal/alertcodes"
	"github.com/girste/chihuaudit/internal/audit"
	"github.com/girste/chihuaudit/internal/baseline"
	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/util"
	"go.uber.org/zap"
)

// DriftMonitor performs baseline-based drift detection
type DriftMonitor struct {
	baselinePath string
	logDir       string
	verbose      bool
	logger       *zap.Logger
}

// NewDriftMonitor creates a new drift monitor
func NewDriftMonitor(logDir string, verbose bool) *DriftMonitor {
	// Use new baseline path (YAML)
	baselinePath := filepath.Join(logDir, "baseline.yaml")

	return &DriftMonitor{
		baselinePath: baselinePath,
		logDir:       logDir,
		verbose:      verbose,
		logger:       util.GetLogger(),
	}
}

// DriftResult represents the result of drift detection
type DriftResult struct {
	Status       string                `json:"status"`
	DriftCount   int                   `json:"drift_count"`
	Alerts       []alertcodes.Alert    `json:"alerts"`
	BulletinFile string                `json:"bulletin_file,omitempty"`
	AnomalyFile  string                `json:"anomaly_file,omitempty"`
}

// CheckDrift performs baseline comparison and detects drifts
func (m *DriftMonitor) CheckDrift(ctx context.Context, cfg *config.Config) (*DriftResult, error) {
	// Run audit to get current state
	orchestrator := audit.NewOrchestrator()
	currentReport, err := orchestrator.RunAudit(ctx, cfg, false)
	if err != nil {
		return nil, fmt.Errorf("audit failed: %w", err)
	}

	// Check if baseline exists
	if !m.baselineExists() {
		// No baseline - create it
		m.log("No baseline found, creating initial baseline...")
		if err := m.createBaseline(currentReport); err != nil {
			return nil, fmt.Errorf("failed to create baseline: %w", err)
		}
		m.log("Baseline created. Drift monitoring will start on next check.")
		return &DriftResult{
			Status:     "baseline_created",
			DriftCount: 0,
			Alerts:     []alertcodes.Alert{},
		}, nil
	}

	// Load baseline
	bl, err := baseline.Load(m.baselinePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load baseline: %w", err)
	}

	// Compare baseline vs current
	diffResult, err := baseline.Compare(bl, currentReport)
	if err != nil {
		return nil, fmt.Errorf("failed to compare baseline: %w", err)
	}

	// Generate alerts with codes
	alerts := alertcodes.GenerateAlerts(diffResult.Drifts)

	// Filter whitelisted alerts
	alerts = m.filterWhitelistedAlerts(cfg, alerts)

	// Calculate baseline age
	baselineTime, _ := time.Parse(time.RFC3339, bl.Metadata.Timestamp)
	baselineAge := time.Since(baselineTime)

	// Determine status
	status := "ok"
	if len(alerts) > 0 {
		// Check severity
		hasCritical := false
		hasHigh := false
		for _, alert := range alerts {
			if alert.Severity == "critical" {
				hasCritical = true
				break
			}
			if alert.Severity == "high" {
				hasHigh = true
			}
		}

		if hasCritical {
			status = "critical"
		} else if hasHigh {
			status = "high"
		} else {
			status = "medium"
		}
	}

	result := &DriftResult{
		Status:     status,
		DriftCount: len(alerts),
		Alerts:     alerts,
	}

	// Generate bulletin if drifts detected
	if len(alerts) > 0 {
		m.log(fmt.Sprintf("Detected %d configuration drifts", len(alerts)))
		
		bulletin := m.generateBulletin(bl, diffResult, alerts, baselineAge)
		bulletinFile := m.writeBulletin(bulletin)
		result.BulletinFile = bulletinFile

		// Write drift report
		driftFile := m.writeDriftReport(alerts, diffResult)
		result.AnomalyFile = driftFile

		if m.verbose {
			fmt.Println("\n" + bulletin + "\n")
			
			if status == "critical" {
				fmt.Fprintf(os.Stderr, "\n🔴 CRITICAL DRIFT DETECTED\n")
				fmt.Fprintf(os.Stderr, "Review drift report: %s\n", driftFile)
			} else if status == "high" {
				fmt.Fprintf(os.Stderr, "\n🟠 HIGH SEVERITY DRIFT DETECTED\n")
				fmt.Fprintf(os.Stderr, "Review drift report: %s\n", driftFile)
			}
		}
	} else {
		m.log("No configuration drifts detected")
	}

	return result, nil
}

// baselineExists checks if baseline file exists
func (m *DriftMonitor) baselineExists() bool {
	_, err := os.Stat(m.baselinePath)
	return err == nil
}

// createBaseline creates initial baseline
func (m *DriftMonitor) createBaseline(auditReport map[string]interface{}) error {
	bl, err := baseline.Create(auditReport, "1.0.0")
	if err != nil {
		return err
	}

	return baseline.Save(bl, m.baselinePath)
}

// filterWhitelistedAlerts filters out whitelisted alert codes
func (m *DriftMonitor) filterWhitelistedAlerts(cfg *config.Config, alerts []alertcodes.Alert) []alertcodes.Alert {
	if cfg.Whitelist == nil {
		return alerts
	}

	filtered := make([]alertcodes.Alert, 0)
	for _, alert := range alerts {
		// Check if alert code is whitelisted
		if cfg.Whitelist.IsAlertWhitelisted(alert.Code) {
			m.log(fmt.Sprintf("Skipping whitelisted alert: %s - %s", alert.Code, alert.Message))
			continue
		}
		filtered = append(filtered, alert)
	}

	m.log(fmt.Sprintf("Filtered %d whitelisted alerts, %d remaining", len(alerts)-len(filtered), len(filtered)))
	return filtered
}

// generateBulletin creates a human-readable bulletin
func (m *DriftMonitor) generateBulletin(bl *baseline.Baseline, diffResult *baseline.DiffResult, alerts []alertcodes.Alert, baselineAge time.Duration) string {
	bulletin := fmt.Sprintf(`
================================================================================
CHIHUAUDIT DRIFT DETECTION REPORT
================================================================================

Baseline Information:
  Created:    %s
  Age:        %.1f hours
  Hostname:   %s
  
Current Check:
  Timestamp:  %s
  Drifts:     %d detected

`,
		bl.Metadata.Timestamp,
		baselineAge.Hours(),
		bl.Metadata.Hostname,
		diffResult.CurrentTimestamp,
		diffResult.DriftCount,
	)

	if len(alerts) == 0 {
		bulletin += "✓ No configuration drifts detected. System matches baseline.\n\n"
		return bulletin
	}

	bulletin += "Configuration Drifts Detected:\n"
	bulletin += "────────────────────────────────────────────────────────────────────────────────\n\n"

	// Group by severity
	critical := []alertcodes.Alert{}
	high := []alertcodes.Alert{}
	medium := []alertcodes.Alert{}
	low := []alertcodes.Alert{}

	for _, alert := range alerts {
		switch alert.Severity {
		case "critical":
			critical = append(critical, alert)
		case "high":
			high = append(high, alert)
		case "medium":
			medium = append(medium, alert)
		default:
			low = append(low, alert)
		}
	}

	// Print by severity
	if len(critical) > 0 {
		bulletin += fmt.Sprintf("🔴 CRITICAL (%d):\n", len(critical))
		for _, alert := range critical {
			bulletin += m.formatAlert(alert)
		}
		bulletin += "\n"
	}

	if len(high) > 0 {
		bulletin += fmt.Sprintf("🟠 HIGH (%d):\n", len(high))
		for _, alert := range high {
			bulletin += m.formatAlert(alert)
		}
		bulletin += "\n"
	}

	if len(medium) > 0 {
		bulletin += fmt.Sprintf("🟡 MEDIUM (%d):\n", len(medium))
		for _, alert := range medium {
			bulletin += m.formatAlert(alert)
		}
		bulletin += "\n"
	}

	if len(low) > 0 {
		bulletin += fmt.Sprintf("🔵 LOW (%d):\n", len(low))
		for _, alert := range low {
			bulletin += m.formatAlert(alert)
		}
	}

	bulletin += "\n"
	bulletin += "================================================================================\n"
	bulletin += "ACTIONS:\n"
	bulletin += "  1. Review each drift and verify it was authorized\n"
	bulletin += "  2. For legitimate changes, update baseline: chihuaudit baseline update\n"
	bulletin += "  3. For unwanted changes, investigate and revert\n"
	bulletin += "  4. Whitelist known-good drifts to suppress alerts\n"
	bulletin += "================================================================================\n"

	return bulletin
}

// formatAlert formats a single alert for display
func (m *DriftMonitor) formatAlert(alert alertcodes.Alert) string {
	output := fmt.Sprintf("  [%s] %s\n", alert.Code, alert.Message)
	output += fmt.Sprintf("    Analyzer: %s | Field: %s | Change: %s\n", alert.Analyzer, alert.Field, alert.ChangeType)
	if alert.Recommendation != "" {
		output += fmt.Sprintf("    → %s\n", alert.Recommendation)
	}
	return output + "\n"
}

// writeBulletin writes bulletin to file
func (m *DriftMonitor) writeBulletin(bulletin string) string {
	timestamp := time.Now().UTC().Format("2006-01-02-150405")
	filename := filepath.Join(m.logDir, fmt.Sprintf("bulletin-%s.txt", timestamp))
	_ = os.WriteFile(filename, []byte(bulletin), 0600)
	return filename
}

// writeDriftReport writes detailed drift report
func (m *DriftMonitor) writeDriftReport(alerts []alertcodes.Alert, diffResult *baseline.DiffResult) string {
	timestamp := time.Now().UTC().Format("2006-01-02-150405")
	filename := filepath.Join(m.logDir, fmt.Sprintf("drift-%s.json", timestamp))
	
	report := map[string]interface{}{
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
		"baseline_timestamp": diffResult.BaselineTimestamp,
		"drift_count":        diffResult.DriftCount,
		"alerts":             alerts,
		"drifts":             diffResult.Drifts,
	}

	data, _ := json.MarshalIndent(report, "", "  ")
	_ = os.WriteFile(filename, data, 0600)
	return filename
}

// log prints log message
func (m *DriftMonitor) log(msg string) {
	if m.verbose {
		timestamp := time.Now().UTC().Format("2006-01-02 15:04:05")
		if m.logger != nil {
			m.logger.Info(msg, zap.String("timestamp", timestamp))
		} else {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", timestamp, msg)
		}
	}
}
