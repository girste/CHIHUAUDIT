package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/girste/mcp-cybersec-watchdog/internal/audit"
	"github.com/girste/mcp-cybersec-watchdog/internal/config"
	"github.com/girste/mcp-cybersec-watchdog/internal/notify"
	"github.com/girste/mcp-cybersec-watchdog/internal/util"
	"go.uber.org/zap"
)

// SecurityMonitor is the continuous monitoring daemon
type SecurityMonitor struct {
	interval        time.Duration
	logDir          string
	verbose         bool
	running         bool
	baselineMgr     *BaselineManager
	anomalyDetector *AnomalyDetector
	bulletinGen     *BulletinGenerator
	logger          *zap.Logger
	stopChan        chan struct{}
}

// NewSecurityMonitor creates a new monitor
func NewSecurityMonitor(intervalSeconds int, logDir, baselinePath string, verbose bool) *SecurityMonitor {
	// Minimum interval (commented out for testing - normally 300 seconds)
	// if intervalSeconds < 300 {
	// 	intervalSeconds = 300 // Minimum 5 minutes
	// }

	// Create log directory
	_ = os.MkdirAll(logDir, 0700)

	// Default baseline path
	if baselinePath == "" {
		baselinePath = filepath.Join(logDir, "baseline.json")
	}

	return &SecurityMonitor{
		interval:        time.Duration(intervalSeconds) * time.Second,
		logDir:          logDir,
		verbose:         verbose,
		baselineMgr:     NewBaselineManager(baselinePath),
		anomalyDetector: NewAnomalyDetector(),
		bulletinGen:     NewBulletinGenerator(),
		logger:          util.GetLogger(),
		stopChan:        make(chan struct{}),
	}
}

// CheckResult represents the result of a single monitoring check
type CheckResult struct {
	Status       string    `json:"status"`
	Anomalies    []Anomaly `json:"anomalies"`
	BulletinFile string    `json:"bulletin_file,omitempty"`
	AnomalyFile  string    `json:"anomaly_file,omitempty"`
}

func (m *SecurityMonitor) log(msg string) {
	if m.verbose {
		timestamp := time.Now().UTC().Format("2006-01-02 15:04:05")
		fmt.Printf("[%s] %s\n", timestamp, msg)
	}
}

// RunOnce performs a single monitoring check
func (m *SecurityMonitor) RunOnce() (*CheckResult, error) {
	m.log("Running security audit...")

	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	orchestrator := audit.NewOrchestrator()
	ctx := context.Background()

	report, err := orchestrator.RunAudit(ctx, cfg, true)
	if err != nil {
		return nil, fmt.Errorf("audit failed: %w", err)
	}

	// Load baseline
	baseline := m.baselineMgr.GetBaseline()

	if baseline == nil {
		// First run - create baseline
		m.log("No baseline found, creating initial baseline...")
		if err := m.baselineMgr.Save(report); err != nil {
			return nil, fmt.Errorf("failed to save baseline: %w", err)
		}
		m.log("Baseline created. Monitoring will start on next check.")
		return &CheckResult{
			Status:    "baseline_created",
			Anomalies: []Anomaly{},
		}, nil
	}

	// Extract comparable snapshots
	currentSnapshot := m.baselineMgr.ExtractComparableData(report)

	// Check system health (services, disk, memory, errors)
	m.log("Checking system health...")
	systemHealth := CheckSystemHealth(ctx, cfg)

	// Detect anomalies (baseline comparison + system health)
	m.log("Checking for anomalies...")
	anomalies := m.anomalyDetector.Detect(baseline.Snapshot, currentSnapshot)

	// Add system health anomalies
	anomalies = append(anomalies, detectSystemHealthAnomalies(systemHealth)...)

	// Calculate baseline age
	baselineTime, _ := time.Parse(time.RFC3339, baseline.Timestamp)
	baselineAge := time.Since(baselineTime)
	baselineAgeHours := baselineAge.Hours()

	// Generate bulletin
	bulletin := m.bulletinGen.Generate(report, anomalies, baselineAgeHours)

	// Print bulletin
	if m.verbose {
		fmt.Println("\n" + bulletin + "\n")
	}

	// Write bulletin to file
	bulletinFile := m.writeBulletin(bulletin)

	// Write anomaly report if detected
	var anomalyFile string
	if len(anomalies) > 0 {
		var status string
		m.log(fmt.Sprintf("Detected %d anomalies", len(anomalies)))
		anomalyFile = m.writeAnomalyReport(anomalies, report)

		if m.anomalyDetector.HasCritical() {
			m.log("CRITICAL anomalies detected - AI analysis recommended")
			if m.verbose {
				status = "critical"
				fmt.Printf("\nCRITICAL ANOMALY DETECTED\n")
				fmt.Printf("Run AI analysis: Use MCP tool 'analyze_anomaly' with file %s\n", anomalyFile)
			}
		} else if m.anomalyDetector.HasHigh() {
			status = "high"
			m.log("High severity anomalies detected - AI analysis recommended")
			if m.verbose {
				fmt.Printf("\nHIGH SEVERITY ANOMALY DETECTED\n")
				fmt.Printf("Run AI analysis: Use MCP tool 'analyze_anomaly' with file %s\n", anomalyFile)
			}
		} else {
			status = "medium"
		}

		// Send webhook notification
		m.sendNotification(ctx, cfg, report, anomalies, status, anomalyFile)
	} else {
		m.log("No anomalies detected - system stable")
	}

	return &CheckResult{
		Status:       "completed",
		Anomalies:    anomalies,
		BulletinFile: bulletinFile,
		AnomalyFile:  anomalyFile,
	}, nil
}

func (m *SecurityMonitor) writeBulletin(bulletin string) string {
	timestamp := time.Now().UTC().Format("20060102_150405")
	filename := filepath.Join(m.logDir, fmt.Sprintf("bulletin_%s.txt", timestamp))

	if err := os.WriteFile(filename, []byte(bulletin), 0600); err != nil {
		m.log(fmt.Sprintf("Failed to write bulletin: %v", err))
		return ""
	}

	m.log(fmt.Sprintf("Bulletin written to %s", filename))
	return filename
}

func (m *SecurityMonitor) writeAnomalyReport(anomalies []Anomaly, report map[string]interface{}) string {
	timestamp := time.Now().UTC().Format("20060102_150405")
	filename := filepath.Join(m.logDir, fmt.Sprintf("anomaly_%s.json", timestamp))

	data := map[string]interface{}{
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"anomalies":   anomalies,
		"full_report": report,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		m.log(fmt.Sprintf("Failed to marshal anomaly report: %v", err))
		return ""
	}

	if err := os.WriteFile(filename, jsonData, 0600); err != nil {
		m.log(fmt.Sprintf("Failed to write anomaly report: %v", err))
		return ""
	}

	m.log(fmt.Sprintf("Anomaly report written to %s", filename))
	return filename
}

// Run starts the continuous monitoring loop
func (m *SecurityMonitor) Run() {
	m.log(fmt.Sprintf("Starting security monitoring (interval: %v)", m.interval))
	m.log(fmt.Sprintf("Logs: %s", m.logDir))
	m.log(fmt.Sprintf("Baseline: %s", m.baselineMgr.GetPath()))

	m.running = true
	checkCount := 0

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigChan
		m.log("Received shutdown signal, stopping...")
		m.running = false
		close(m.stopChan)
	}()

	for m.running {
		checkCount++
		m.log(fmt.Sprintf("--- Check #%d ---", checkCount))

		result, err := m.RunOnce()
		if err != nil {
			m.log(fmt.Sprintf("Error during check: %v", err))
		} else {
			m.log(fmt.Sprintf("Check completed: %s", result.Status))
		}

		// Auto-cleanup every 10 checks
		if checkCount%10 == 0 {
			m.log("Running automatic log cleanup...")
			manager := NewMonitoringManager(m.logDir)
			cleanupResult := manager.CleanupOldLogs(50, 20)
			if cleanupResult.BulletinsRemoved > 0 || cleanupResult.AnomaliesRemoved > 0 {
				m.log(fmt.Sprintf("Cleaned up %d bulletins, %d anomalies",
					cleanupResult.BulletinsRemoved, cleanupResult.AnomaliesRemoved))
			}
		}

		// Wait for next interval or stop signal
		if m.running {
			m.log(fmt.Sprintf("Sleeping for %v...", m.interval))
			select {
			case <-time.After(m.interval):
			case <-m.stopChan:
			}
		}
	}

	m.log("Monitoring stopped")
}

// Stop signals the monitor to stop
func (m *SecurityMonitor) Stop() {
	m.running = false
	close(m.stopChan)
}

// ResetBaseline forces baseline recreation on next check
func (m *SecurityMonitor) ResetBaseline() error {
	path := m.baselineMgr.GetPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	m.log("Baseline reset - will be recreated on next check")
	return nil
}

// sendNotification sends webhook notifications for anomalies
func (m *SecurityMonitor) sendNotification(ctx context.Context, cfg *config.Config, report map[string]interface{}, anomalies []Anomaly, status, anomalyFile string) {
	if !cfg.Notifications.Enabled {
		return
	}

	notifier := notify.NewNotifier(&cfg.Notifications)
	if !notifier.ShouldNotify(status, len(anomalies) > 0) {
		return
	}

	// Build alert payload
	hostname := "unknown"
	if h, ok := report["hostname"].(string); ok {
		hostname = h
	}

	// Calculate score from analysis
	score := 100
	if analysis, ok := report["analysis"].(map[string]interface{}); ok {
		if scoreData, ok := analysis["score"].(map[string]int); ok {
			// Deduct points for issues
			score -= scoreData["criticalIssues"] * 25
			score -= scoreData["highPriorityIssues"] * 10
			score -= scoreData["mediumIssues"] * 3
			if score < 0 {
				score = 0
			}
		}
	}

	// Convert anomalies to alert issues
	issues := make([]notify.AlertIssue, 0, len(anomalies))
	for _, a := range anomalies {
		issues = append(issues, notify.AlertIssue{
			Severity: a.Severity,
			Message:  a.Message,
			Category: a.Category,
		})
	}

	// Build positives from report
	positives := []string{}
	if fwData, ok := report["firewall"].(map[string]interface{}); ok {
		if active, ok := fwData["active"].(bool); ok && active {
			positives = append(positives, "Firewall active")
		}
	}
	if sshData, ok := report["ssh"].(map[string]interface{}); ok {
		if rootLogin, ok := sshData["permit_root_login"].(string); ok && rootLogin == "no" {
			positives = append(positives, "Root SSH login disabled")
		}
	}
	if f2bData, ok := report["fail2ban"].(map[string]interface{}); ok {
		if active, ok := f2bData["active"].(bool); ok && active {
			positives = append(positives, "Fail2ban active")
		}
	}

	alert := &notify.AlertPayload{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Hostname:    hostname,
		Status:      status,
		Score:       score,
		Title:       "Security Alert: Anomalies Detected",
		Summary:     fmt.Sprintf("Detected %d security anomalies on %s", len(anomalies), hostname),
		Issues:      issues,
		Positives:   positives,
		AnomalyFile: anomalyFile,
	}

	result := notifier.Send(ctx, alert)
	if len(result.Sent) > 0 {
		m.log(fmt.Sprintf("Notifications sent to: %v", result.Sent))
	}
	if len(result.Failed) > 0 {
		for _, f := range result.Failed {
			m.log(fmt.Sprintf("Notification failed for %s: %s", f.Provider, f.Error))
		}
	}
}
