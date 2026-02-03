package monitoring

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/girste/chihuaudit/internal/alertcodes"
	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/notify"
	"github.com/girste/chihuaudit/internal/util"
	"go.uber.org/zap"
)

// SecurityMonitor is the continuous monitoring daemon.
type SecurityMonitor struct {
	interval     time.Duration
	logDir       string
	verbose      bool
	running      bool
	driftMonitor *DriftMonitor
	notifTracker *NotificationTracker
	logger       *zap.Logger
	stopChan     chan struct{}
}

// NewSecurityMonitor creates a new monitor.
func NewSecurityMonitor(intervalSeconds int, logDir string, verbose bool) *SecurityMonitor {
	_ = os.MkdirAll(logDir, 0700)

	tracker := NewNotificationTracker(logDir)
	_ = tracker.Load()

	return &SecurityMonitor{
		interval:     time.Duration(intervalSeconds) * time.Second,
		logDir:       logDir,
		verbose:      verbose,
		driftMonitor: NewDriftMonitor(logDir, verbose),
		notifTracker: tracker,
		logger:       util.GetLogger(),
		stopChan:     make(chan struct{}),
	}
}

// CheckResult represents the result of a single monitoring check.
type CheckResult struct {
	Status       string               `json:"status"`
	Anomalies    []alertcodes.Alert   `json:"anomalies"`
	BulletinFile string               `json:"bulletin_file,omitempty"`
	AnomalyFile  string               `json:"anomaly_file,omitempty"`
}

func (m *SecurityMonitor) log(msg string) {
	if m.verbose {
		timestamp := time.Now().UTC().Format("2006-01-02 15:04:05")
		if m.logger != nil {
			m.logger.Info(msg, zap.String("timestamp", timestamp))
		} else {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", timestamp, msg)
		}
	}
}

// RunOnce performs a single monitoring check.
func (m *SecurityMonitor) RunOnce() (*CheckResult, error) {
	m.log("Running security audit...")

	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return m.runDriftCheck(cfg)
}

// runDriftCheck performs baseline drift detection via DriftMonitor.
func (m *SecurityMonitor) runDriftCheck(cfg *config.Config) (*CheckResult, error) {
	ctx := context.Background()

	driftResult, err := m.driftMonitor.CheckDrift(ctx, cfg)
	if err != nil {
		return nil, err
	}

	result := &CheckResult{
		Status:       driftResult.Status,
		BulletinFile: driftResult.BulletinFile,
		AnomalyFile:  driftResult.AnomalyFile,
		Anomalies:    driftResult.Alerts,
	}

	if len(driftResult.Alerts) > 0 {
		m.sendDriftNotification(ctx, cfg, driftResult, result.AnomalyFile)
	}

	return result, nil
}

// Run starts the continuous monitoring loop.
func (m *SecurityMonitor) Run() {
	m.log(fmt.Sprintf("Starting security monitoring (interval: %v)", m.interval))
	m.log(fmt.Sprintf("Logs: %s", m.logDir))
	m.log(fmt.Sprintf("Baseline: %s", m.driftMonitor.baselinePath))

	m.running = true
	checkCount := 0

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

// Stop signals the monitor to stop.
func (m *SecurityMonitor) Stop() {
	m.running = false
	close(m.stopChan)
}

// sendDriftNotification sends webhook notification for detected drifts.
func (m *SecurityMonitor) sendDriftNotification(ctx context.Context, cfg *config.Config, driftResult *DriftResult, driftFile string) {
	if !cfg.Notifications.Enabled {
		return
	}

	// Cooldown check — only notify if first occurrence or 24 h elapsed
	if len(driftResult.Alerts) > 0 {
		firstAlert := driftResult.Alerts[0]
		if !m.notifTracker.ShouldNotify(firstAlert) {
			m.log("Skipping notification (cooldown active)")
			return
		}
	}

	issues := make([]notify.AlertIssue, 0, len(driftResult.Alerts))
	for _, alert := range driftResult.Alerts {
		issues = append(issues, notify.AlertIssue{
			Code:     alert.Code,
			Severity: string(alert.Severity),
			Message:  alert.Message,
			Category: alert.Analyzer,
		})
	}

	hostname, _ := os.Hostname()

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
