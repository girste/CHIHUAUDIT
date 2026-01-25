package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/girste/mcp-cybersec-watchdog/internal/audit"
	"github.com/girste/mcp-cybersec-watchdog/internal/config"
	"github.com/girste/mcp-cybersec-watchdog/internal/mcp"
	"github.com/girste/mcp-cybersec-watchdog/internal/monitoring"
	"github.com/girste/mcp-cybersec-watchdog/internal/notify"
	"github.com/girste/mcp-cybersec-watchdog/internal/output"
	"github.com/girste/mcp-cybersec-watchdog/internal/system"
)

var version = "1.0.0"

func main() {
	if len(os.Args) > 1 {
		command := os.Args[1]

		switch command {
		case "version", "--version", "-v":
			fmt.Printf("mcp-watchdog version %s\n", version)
			os.Exit(0)

		case "test":
			runTest()
			os.Exit(0)

		case "audit":
			exitCode := runAudit()
			os.Exit(exitCode)

		case "verify":
			runVerify()
			os.Exit(0)

		case "monitor":
			runMonitor()
			os.Exit(0)

		case "monitor-once":
			runMonitorOnce()
			os.Exit(0)

		case "monitor-status":
			runMonitorStatus()
			os.Exit(0)

		case "help", "--help", "-h":
			printHelp()
			os.Exit(0)

		default:
			fmt.Printf("Unknown command: %s\n", command)
			printHelp()
			os.Exit(1)
		}
	}

	// Default: run as MCP server
	runServer()
}

func runServer() {
	server, err := mcp.NewServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create MCP server: %v\n", err)
		os.Exit(1)
	}

	if err := server.Serve(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func runTest() {
	fmt.Println("Running security audit...")

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	orchestrator := audit.NewOrchestrator()
	ctx := context.Background()

	report, err := orchestrator.RunAudit(ctx, cfg, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Audit failed: %v\n", err)
		os.Exit(1)
	}

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to format report: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(reportJSON))
}

// runAudit runs the audit with the new standardized output format
// Returns exit code: 0=ok, 1=warning, 2=critical
func runAudit() int {
	// Parse flags
	formatType := "text"
	quiet := false
	aiMode := false
	webhookOnly := false
	onIssuesOnly := false
	includeRaw := false

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case strings.HasPrefix(arg, "--format="):
			formatType = strings.TrimPrefix(arg, "--format=")
		case arg == "--format" && i+1 < len(os.Args):
			formatType = os.Args[i+1]
			i++
		case arg == "--quiet" || arg == "-q":
			quiet = true
		case arg == "--ai":
			aiMode = true
		case arg == "--webhook":
			webhookOnly = true
		case arg == "--on-issues":
			onIssuesOnly = true
		case arg == "--raw":
			includeRaw = true
		case arg == "--help" || arg == "-h":
			printAuditHelp()
			return 0
		}
	}

	cfg, err := config.Load()
	if err != nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		}
		return 2
	}

	orchestrator := audit.NewOrchestrator()
	ctx := context.Background()

	rawReport, err := orchestrator.RunAudit(ctx, cfg, true)
	if err != nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "Audit failed: %v\n", err)
		}
		return 2
	}

	// Format report
	formatter := output.NewFormatter(formatType, aiMode, !quiet)
	report := formatter.FormatReport(rawReport)

	exitCode := formatter.GetExitCode(report)

	// Check if we should skip output (on-issues mode with no issues)
	if onIssuesOnly && exitCode == 0 {
		return 0
	}

	// Send webhook notification if configured
	if cfg.Notifications.Enabled || webhookOnly {
		notifier := notify.NewNotifier(&cfg.Notifications)
		hasIssues := len(report.Negatives) > 0

		if notifier.ShouldNotify(report.TrafficLight.Status, hasIssues) || webhookOnly {
			issues := make([]notify.AlertIssue, 0, len(report.Negatives))
			for _, n := range report.Negatives {
				issues = append(issues, notify.AlertIssue{
					Severity: n.Severity,
					Message:  n.Message,
					Category: n.Category,
				})
			}

			// Convert traffic light status to severity level
			statusSeverity := "ok"
			if report.TrafficLight.Status == "red" {
				// Check for critical issues
				hasCritical := false
				for _, n := range report.Negatives {
					if n.Severity == "critical" {
						hasCritical = true
						break
					}
				}
				if hasCritical {
					statusSeverity = "critical"
				} else {
					statusSeverity = "high"
				}
			} else if report.TrafficLight.Status == "yellow" {
				statusSeverity = "medium"
			}

			alert := &notify.AlertPayload{
				Timestamp: report.Timestamp,
				Hostname:  report.Hostname,
				Status:    statusSeverity,
				Score:     report.Score.Value,
				Title:     "Security Audit Report",
				Summary:   fmt.Sprintf("Security score: %d/100 (%s)", report.Score.Value, report.Score.Grade),
				Issues:    issues,
				Positives: report.Positives,
			}

			result := notifier.Send(ctx, alert)
			if !quiet && len(result.Sent) > 0 {
				fmt.Fprintf(os.Stderr, "Notifications sent to: %v\n", result.Sent)
			}
		}
	}

	// If webhook only mode, don't print output
	if webhookOnly {
		return exitCode
	}

	// Output based on format
	if !quiet {
		switch formatType {
		case "json":
			jsonOut, _ := formatter.ToJSON(report, includeRaw)
			fmt.Println(jsonOut)
		case "summary":
			fmt.Println(formatter.ToSummary(report))
		case "compact":
			fmt.Printf("%s %d %s\n", report.TrafficLight.Status, report.Score.Value, report.Hostname)
		default: // text
			fmt.Print(formatter.ToText(report))
		}
	}

	return exitCode
}

func printAuditHelp() {
	help := `mcp-watchdog audit - Run security audit with standardized output

USAGE:
    mcp-watchdog audit [OPTIONS]

OPTIONS:
    --format=FORMAT    Output format: text, json, summary, compact (default: text)
    --quiet, -q        Suppress output (only return exit code)
    --ai               Enable AI mode (includes recommendations)
    --webhook          Send webhook notification (ignores quiet mode)
    --on-issues        Only output/notify when issues are found
    --raw              Include raw report data in JSON output

EXIT CODES:
    0    OK - System security is good (green)
    1    WARNING - Issues need attention (yellow)
    2    CRITICAL - Immediate action required (red)

EXAMPLES:
    # Standard text output
    mcp-watchdog audit

    # JSON output for scripts
    mcp-watchdog audit --format=json

    # One-line summary for monitoring
    mcp-watchdog audit --format=summary

    # Cron job: only notify on issues, no output
    mcp-watchdog audit --quiet --webhook --on-issues

    # Full report with AI recommendations
    mcp-watchdog audit --ai

    # Exit code only (for scripting)
    mcp-watchdog audit --quiet && echo "OK" || echo "ISSUES"
`
	fmt.Print(help)
}

func runVerify() {
	fmt.Println("Verifying security audit prerequisites...")

	ctx := context.Background()

	// Check OS
	osInfo := system.GetOSInfo(ctx)
	fmt.Printf("  OS detected: %s (%s)\n", osInfo.System, osInfo.Distro)
	fmt.Printf("  Kernel: %s\n", osInfo.Kernel)

	// Check key commands
	commands := []string{"ufw", "iptables", "ss", "systemctl", "docker"}
	fmt.Println("\nChecking commands:")
	for _, cmd := range commands {
		if system.CommandExists(cmd) {
			fmt.Printf("  [OK] %s\n", cmd)
		} else {
			fmt.Printf("  [--] %s (not found)\n", cmd)
		}
	}

	// Check sudo access
	fmt.Println("\nChecking sudo access:")
	result, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "echo", "test")
	if result != nil && result.Success {
		fmt.Println("  [OK] Sudo access configured")
	} else {
		fmt.Println("  [!!] Sudo access not configured")
		fmt.Println("\nRun setup-sudo.sh to configure passwordless sudo for security checks")
	}

	fmt.Println("\nVerification complete!")
}

func runMonitor() {
	// Parse arguments
	interval := 3600
	logDir := getLogDir()

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		if (arg == "--interval" || arg == "-i") && i+1 < len(os.Args) {
			if v, err := strconv.Atoi(os.Args[i+1]); err == nil {
				interval = v
			}
			i++
		} else if (arg == "--log-dir" || arg == "-d") && i+1 < len(os.Args) {
			logDir = os.Args[i+1]
			i++
		}
	}

	fmt.Printf("Starting security monitor (interval: %ds)\n", interval)
	fmt.Printf("Logs will be written to: %s\n", logDir)
	fmt.Println("Press Ctrl+C to stop")

	baselinePath := logDir + "/baseline.json"
	monitor := monitoring.NewSecurityMonitor(interval, logDir, baselinePath, true)
	monitor.Run()
}

func runMonitorOnce() {
	logDir := getLogDir()

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		if (arg == "--log-dir" || arg == "-d") && i+1 < len(os.Args) {
			logDir = os.Args[i+1]
			i++
		}
	}

	baselinePath := logDir + "/baseline.json"
	monitor := monitoring.NewSecurityMonitor(3600, logDir, baselinePath, true)

	result, err := monitor.RunOnce()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Monitor check failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nCheck result: %s\n", result.Status)
	if result.AnomalyFile != "" {
		fmt.Printf("Anomaly file: %s\n", result.AnomalyFile)
	}
}

func runMonitorStatus() {
	logDir := getLogDir()
	manager := monitoring.NewMonitoringManager(logDir)
	status := manager.GetStatus()

	statusJSON, _ := json.MarshalIndent(status, "", "  ")
	fmt.Println(string(statusJSON))
}

func getLogDir() string {
	if os.Geteuid() == 0 {
		return "/var/log/mcp-watchdog"
	}
	return fmt.Sprintf("/tmp/mcp-watchdog-%d", os.Getuid())
}

func printHelp() {
	help := `mcp-watchdog - Cybersecurity monitoring and analysis for Linux servers

USAGE:
    mcp-watchdog [COMMAND]

COMMANDS:
    (none)          Run as MCP server (default)
    audit           Run security audit with standardized output (recommended)
    test            Run one-time security audit (legacy JSON output)
    verify          Verify prerequisites and configuration
    monitor         Start continuous monitoring daemon
    monitor-once    Run single monitoring check
    monitor-status  Show monitoring daemon status
    version         Show version information
    help            Show this help message

AUDIT OPTIONS (mcp-watchdog audit):
    --format=FORMAT   Output format: text, json, summary, compact
    --quiet, -q       Suppress output (return exit code only)
    --ai              Enable AI mode (includes recommendations)
    --webhook         Send webhook notification
    --on-issues       Only output/notify when issues are found

    Exit codes: 0=OK (green), 1=WARNING (yellow), 2=CRITICAL (red)

MONITOR OPTIONS:
    --interval, -i SECONDS   Check interval (default: 3600, min: 300)
    --log-dir, -d PATH       Log directory

EXAMPLES:
    # Run as MCP server (for Claude Desktop)
    mcp-watchdog

    # Run security audit with visual output
    sudo mcp-watchdog audit

    # Cron job: notify via webhook only when issues found
    sudo mcp-watchdog audit --quiet --webhook --on-issues

    # Get JSON output for scripts
    sudo mcp-watchdog audit --format=json

    # One-line summary for monitoring dashboards
    sudo mcp-watchdog audit --format=summary

    # Start continuous monitoring (1 hour interval)
    sudo mcp-watchdog monitor

CONFIGURATION:
    Config file locations (in order of priority):
    - .mcp-watchdog.yaml (current directory)
    - ~/.mcp-watchdog.yaml (home directory)
    - /etc/mcp-watchdog/config.yaml (system-wide)

For more information, visit: https://github.com/girste/mcp-cybersec-watchdog
`
	fmt.Print(help)
}
