package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/girste/chihuaudit/internal/audit"
	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/notify"
	"github.com/girste/chihuaudit/internal/util"
	"go.uber.org/zap"
)

// SecurityMonitor is the continuous monitoring daemon
type SecurityMonitor struct {
	interval        time.Duration
	logDir          string
	verbose         bool
	running         bool
	baselineMgr     *BaselineManager
	driftMonitor    *DriftMonitor    // New baseline-based drift detection
	anomalyDetector *AnomalyDetector
	bulletinGen     *BulletinGenerator
	notifTracker    *NotificationTracker
	logger          *zap.Logger
	stopChan        chan struct{}
	useDriftMode    bool // Toggle between old anomaly detection and new drift detection
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

	// Create notification tracker and load state
	tracker := NewNotificationTracker(logDir)
	_ = tracker.Load() // Ignore error on first run

	return &SecurityMonitor{
		interval:        time.Duration(intervalSeconds) * time.Second,
		logDir:          logDir,
		verbose:         verbose,
		baselineMgr:     NewBaselineManager(baselinePath),
		driftMonitor:    NewDriftMonitor(logDir, verbose),
		anomalyDetector: NewAnomalyDetector(),
		bulletinGen:     NewBulletinGenerator(),
		notifTracker:    tracker,
		logger:          util.GetLogger(),
		stopChan:        make(chan struct{}),
		useDriftMode:    true, // Use new drift detection by default
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
		// Use logger for consistency, fallback to stderr if logger unavailable
		if m.logger != nil {
			m.logger.Info(msg, zap.String("timestamp", timestamp))
		} else {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", timestamp, msg)
		}
	}
}

// RunOnce performs a single monitoring check
func (m *SecurityMonitor) RunOnce() (*CheckResult, error) {
	m.log("Running security audit...")

	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Use new drift-based monitoring if enabled
	if m.useDriftMode {
		return m.runDriftCheck(cfg)
	}

	// Otherwise use legacy anomaly detection
	return m.runLegacyCheck(cfg)
}

// runDriftCheck performs baseline drift detection
func (m *SecurityMonitor) runDriftCheck(cfg *config.Config) (*CheckResult, error) {
	ctx := context.Background()
	
	driftResult, err := m.driftMonitor.CheckDrift(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Convert DriftResult to CheckResult for compatibility
	result := &CheckResult{
		Status:       driftResult.Status,
		BulletinFile: driftResult.BulletinFile,
		AnomalyFile:  driftResult.AnomalyFile,
	}

	// Convert alerts to anomalies for notification compatibility
	anomalies := make([]Anomaly, len(driftResult.Alerts))
	for i, alert := range driftResult.Alerts {
		anomalies[i] = Anomaly{
			Code:     alert.Code,
			Severity: string(alert.Severity),
			Category: alert.Analyzer,
			Message:  alert.Message,
		}
	}
	result.Anomalies = anomalies

	// Send notification if drifts detected
	if len(driftResult.Alerts) > 0 {
		m.sendDriftNotification(ctx, cfg, driftResult, result.AnomalyFile)
	}

	return result, nil
}

// runLegacyCheck performs legacy anomaly detection
func (m *SecurityMonitor) runLegacyCheck(cfg *config.Config) (*CheckResult, error) {
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

	// Filter out whitelisted anomalies
	anomalies = m.filterWhitelistedAnomalies(cfg, anomalies, currentSnapshot)

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
				fmt.Fprintf(os.Stderr, "\nCRITICAL ANOMALY DETECTED\n")
				fmt.Fprintf(os.Stderr, "Run AI analysis: Use MCP tool 'analyze_anomaly' with file %s\n", anomalyFile)
			}
		} else if m.anomalyDetector.HasHigh() {
			status = "high"
			m.log("High severity anomalies detected - AI analysis recommended")
			if m.verbose {
				fmt.Fprintf(os.Stderr, "\nHIGH SEVERITY ANOMALY DETECTED\n")
				fmt.Fprintf(os.Stderr, "Run AI analysis: Use MCP tool 'analyze_anomaly' with file %s\n", anomalyFile)
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

	// Filter anomalies through notification tracker (exponential backoff)
	// Only notify if:
	// - First time seeing this anomaly
	// - Last notification was >= 24h ago
	filteredAnomalies := []Anomaly{}
	for _, a := range anomalies {
		if m.notifTracker.ShouldNotify(a) {
			filteredAnomalies = append(filteredAnomalies, a)
		}
	}

	// If all anomalies were filtered out (already notified recently), skip
	if len(filteredAnomalies) == 0 {
		m.log("All anomalies already notified recently, skipping notification")
		return
	}

	// Convert filtered anomalies to alert issues
	issues := make([]notify.AlertIssue, 0, len(filteredAnomalies))
	for _, a := range filteredAnomalies {
		issues = append(issues, notify.AlertIssue{
			Code:     a.Code,
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

	// Save notification tracker state
	if err := m.notifTracker.Save(); err != nil {
		m.log(fmt.Sprintf("Warning: failed to save notification state: %v", err))
	}
}

// filterWhitelistedAnomalies removes anomalies for whitelisted ports/services
func (m *SecurityMonitor) filterWhitelistedAnomalies(cfg *config.Config, anomalies []Anomaly, currentSnapshot map[string]interface{}) []Anomaly {
	if cfg.Whitelist == nil {
		return anomalies
	}

	filtered := []Anomaly{}
	for _, anomaly := range anomalies {
		// Check if this is a "New services listening" anomaly
		if anomaly.Category == "services" && strings.Contains(anomaly.Message, "Port ") {
			// Extract port details from enriched data
			if details, ok := anomaly.Details["enriched"].([]interface{}); ok && len(details) > 0 {
				allWhitelisted := true
				for _, d := range details {
					if portDetail, ok := d.(map[string]interface{}); ok {
						port := int(portDetail["port"].(float64))
						bind := portDetail["bind"].(string)
						process := ""
						if p, ok := portDetail["process"].(string); ok {
							process = p
						}

						// Check whitelist based on bind address and process
						isWhitelisted := false

						// First check if process is whitelisted (takes precedence)
						if process != "" && process != "unknown" {
							isWhitelisted = cfg.Whitelist.IsProcessAllowed(process, bind)
						}

						// If not whitelisted by process, check port-based whitelist
						if !isWhitelisted {
							if bind == "127.0.0.1" || strings.HasPrefix(bind, "127.") {
								// Localhost port
								isWhitelisted = cfg.Whitelist.IsLocalhostPortAllowed(port)
							} else if bind == "0.0.0.0" || bind == "::" {
								// Wildcard port
								isWhitelisted = cfg.Whitelist.IsWildcardPortAllowed(port)
							}
						}

						if !isWhitelisted {
							allWhitelisted = false
							break
						}
					}
				}

				// If all ports in this anomaly are whitelisted, skip it
				if allWhitelisted {
					m.log(fmt.Sprintf("Skipping whitelisted anomaly: %s", anomaly.Message))
					continue
				}
			}
		}

		// Keep this anomaly
		filtered = append(filtered, anomaly)
	}

	return filtered
}

// sendDriftNotification sends webhook notification for detected drifts
func (m *SecurityMonitor) sendDriftNotification(ctx context.Context, cfg *config.Config, driftResult *DriftResult, driftFile string) {
if !cfg.Notifications.Enabled {
return
}

// Check notification cooldown for first drift
if len(driftResult.Alerts) > 0 {
firstAnomaly := Anomaly{
Code:     driftResult.Alerts[0].Code,
Severity: string(driftResult.Alerts[0].Severity),
Category: driftResult.Alerts[0].Analyzer,
Message:  driftResult.Alerts[0].Message,
}

if !m.notifTracker.ShouldNotify(firstAnomaly) {
m.log("Skipping notification (cooldown active)")
return
}
}

// Create notification payload
issues := make([]notify.AlertIssue, 0, len(driftResult.Alerts))
for _, alert := range driftResult.Alerts {
issues = append(issues, notify.AlertIssue{
Code:     alert.Code,
Severity: string(alert.Severity),
Message:  alert.Message,
Category: alert.Analyzer,
})
}

hostname := "unknown"

payload := &notify.AlertPayload{
Timestamp: time.Now().UTC().Format(time.RFC3339),
Hostname:  hostname,
Status:    driftResult.Status,
Title:     fmt.Sprintf("Configuration Drift Detected (%d changes)", driftResult.DriftCount),
Summary:   fmt.Sprintf("%d configuration drifts detected", driftResult.DriftCount),
Issues:    issues,
}

notifier := notify.NewNotifier(&cfg.Notifications)
result := notifier.Send(ctx, payload)

if len(result.Sent) > 0 {
m.log(fmt.Sprintf("Drift notification sent to: %v", result.Sent))
_ = m.notifTracker.Save()
}

if len(result.Failed) > 0 {
m.log(fmt.Sprintf("Failed to send notifications to: %v", result.Failed))
}
}
