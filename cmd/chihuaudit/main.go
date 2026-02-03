package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/girste/chihuaudit/internal/alertcodes"
	"github.com/girste/chihuaudit/internal/audit"
	"github.com/girste/chihuaudit/internal/baseline"
	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/mcp"
	"github.com/girste/chihuaudit/internal/monitoring"
	"github.com/girste/chihuaudit/internal/notify"
	"github.com/girste/chihuaudit/internal/output"
	"github.com/girste/chihuaudit/internal/system"
	"gopkg.in/yaml.v3"
)

var version = "1.0.0"

func main() {
	if len(os.Args) > 1 {
		command := os.Args[1]

		switch command {
		case "version", "--version", "-v":
			fmt.Printf("chihuaudit version %s\n", version)
			os.Exit(0)

		case "test":
			runTest()
			os.Exit(0)

		case "audit":
			exitCode := runAudit()
			os.Exit(exitCode)

		case "serve":
			runServe()
			os.Exit(0)

		case "verify":
			runVerify()
			os.Exit(0)

		case "monitor-once":
			runMonitorOnce()
			os.Exit(0)

		case "monitor-status":
			runMonitorStatus()
			os.Exit(0)

		case "daemon":
			runDaemon()
			os.Exit(0)

		case "baseline":
			runBaseline()
			os.Exit(0)

		case "whitelist":
			runWhitelist()
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
	// Setup context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	server, err := mcp.NewServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create MCP server: %v\n", err)
		os.Exit(1)
	}

	// Run server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Serve()
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		fmt.Fprintf(os.Stderr, "\nReceived %s signal, shutting down gracefully...\n", sig)
		_ = ctx // Context reserved for future cleanup
		cancel()

		// TODO: Add server.Shutdown(ctx) when MCP library supports it
		// For now, exit cleanly
		os.Exit(0)

	case err := <-errChan:
		if err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			_ = ctx // Context reserved for future cleanup
			cancel()
			os.Exit(1)
		}
		cancel()
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

// runServe starts MCP server with pre-generated audit data (NO sudo required)
func runServe() {
	inputFile := ""

	// Parse flags
	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case strings.HasPrefix(arg, "--input="):
			inputFile = strings.TrimPrefix(arg, "--input=")
		case arg == "--input" && i+1 < len(os.Args):
			inputFile = os.Args[i+1]
			i++
		case arg == "--help" || arg == "-h":
			printServeHelp()
			return
		}
	}

	// Read audit report from file or stdin
	var reportData []byte
	var err error

	if inputFile != "" && inputFile != "-" {
		reportData, err = os.ReadFile(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read input file: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Read from stdin
		reportData, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read from stdin: %v\n", err)
			os.Exit(1)
		}
	}

	// Parse JSON
	var rawReport map[string]interface{}
	if err := json.Unmarshal(reportData, &rawReport); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Starting MCP server with pre-loaded audit data (no sudo required)...\n")

	// Setup context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create MCP server with pre-loaded data
	server, err := mcp.NewServerWithData(rawReport)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create MCP server: %v\n", err)
		os.Exit(1)
	}

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	// Run server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Serve()
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		fmt.Fprintf(os.Stderr, "\nReceived %s signal, shutting down gracefully...\n", sig)
		_ = ctx // Context reserved for future cleanup
		cancel()
		os.Exit(0)

	case err := <-errChan:
		if err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			cancel()
			os.Exit(1)
		}
		cancel()
	}
}

func printServeHelp() {
	help := `chihuaudit serve - Start MCP server with pre-generated audit data

USAGE:
    chihuaudit serve [OPTIONS]

DESCRIPTION:
    Starts MCP server using audit data from file or stdin.
    This mode does NOT require sudo and provides privilege separation.

OPTIONS:
    --input=FILE     Read audit data from file (use '-' for stdin)

EXAMPLES:
    # Serve from file (privilege separation)
    sudo chihuaudit audit --format=json --output /tmp/audit.json
    chihuaudit serve --input /tmp/audit.json

    # Pipe mode (real-time)
    sudo chihuaudit audit --format=json | chihuaudit serve

    # Using stdin explicitly
    sudo chihuaudit audit --format=json > /tmp/audit.json
    cat /tmp/audit.json | chihuaudit serve --input -

PRIVILEGE SEPARATION:
    This command provides security through OS-level process separation:

    Process 1 (with sudo):     sudo chihuaudit audit
                               - Collects system data
                               - Analyzes security posture
                               - Writes JSON output
                               - Exits (sudo ends)

    Process 2 (no sudo):       chihuaudit serve
                               - Reads JSON data
                               - Serves MCP protocol
                               - No system access
                               - Never had sudo

    If MCP server is compromised, attacker has NO sudo access.
`
	fmt.Print(help)
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
	outputFile := ""

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case strings.HasPrefix(arg, "--format="):
			formatType = strings.TrimPrefix(arg, "--format=")
		case arg == "--format" && i+1 < len(os.Args):
			formatType = os.Args[i+1]
			i++
		case strings.HasPrefix(arg, "--output="):
			outputFile = strings.TrimPrefix(arg, "--output=")
		case arg == "--output" && i+1 < len(os.Args):
			outputFile = os.Args[i+1]
			i++
		case arg == "--quiet" || arg == "-q":
			quiet = true
		case arg == "--ai":
			aiMode = true
		case arg == "--webhook":
			webhookOnly = true
		case arg == "--on-issues":
			onIssuesOnly = true
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

	// Handle output
	var outputData string

	switch formatType {
	case "json":
		// For JSON, output raw report (not formatted) for serve mode compatibility
		if outputFile != "" || !quiet {
			rawJSON, _ := json.MarshalIndent(rawReport, "", "  ")
			outputData = string(rawJSON)
		}
	case "sarif":
		// SARIF 2.1.0 format for GitHub/GitLab integration
		structuredFormatter := output.NewStructuredFormatter()
		structuredReport := structuredFormatter.FormatReportStructured(rawReport)
		sarifReport := output.ConvertToSARIF(structuredReport, report.Hostname)
		outputData, _ = sarifReport.ToJSON()
	case "summary":
		if !quiet {
			outputData = formatter.ToSummary(report)
		}
	case "compact":
		if !quiet {
			outputData = fmt.Sprintf("%s %d %s\n", report.TrafficLight.Status, report.Score.Value, report.Hostname)
		}
	default: // text
		if !quiet {
			outputData = formatter.ToText(report)
		}
	}

	// Write to file if specified
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(outputData), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write output file: %v\n", err)
			return 2
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "Audit data written to: %s\n", outputFile)
		}
	} else if !quiet && !webhookOnly {
		// Print to stdout
		fmt.Print(outputData)
	}

	return exitCode
}

func printAuditHelp() {
	help := `chihuaudit audit - Run security audit with standardized output

USAGE:
    chihuaudit audit [OPTIONS]

OPTIONS:
    --format=FORMAT    Output format: text, json, sarif, summary, compact (default: text)
    --output=FILE      Write output to file (enables privilege separation with serve)
    --quiet, -q        Suppress output (only return exit code)
    --ai               Enable AI mode (includes recommendations)
    --webhook          Send webhook notification (ignores quiet mode)
    --on-issues        Only output/notify when issues are found

FORMATS:
    text      Human-readable report with colors and formatting
    json      Machine-readable JSON (for serve mode or scripts)
    sarif     SARIF 2.1.0 format (for GitHub/GitLab Code Scanning)
    summary   One-line summary for monitoring
    compact   Minimal output (status score hostname)

EXIT CODES:
    0    OK - System security is good (green)
    1    WARNING - Issues need attention (yellow)
    2    CRITICAL - Immediate action required (red)

EXAMPLES:
    # Standard text output
    chihuaudit audit

    # JSON output for scripts
    chihuaudit audit --format=json

    # One-line summary for monitoring
    chihuaudit audit --format=summary

    # Cron job: only notify on issues, no output
    chihuaudit audit --quiet --webhook --on-issues

    # Full report with AI recommendations
    chihuaudit audit --ai

    # Exit code only (for scripting)
    chihuaudit audit --quiet && echo "OK" || echo "ISSUES"
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

func runDaemon() {
	if len(os.Args) < 3 {
		printDaemonHelp()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "start":
		runDaemonStart()
	case "stop":
		runDaemonStop()
	case "status":
		runDaemonStatus()
	case "help", "--help", "-h":
		printDaemonHelp()
	default:
		fmt.Printf("Unknown daemon subcommand: %s\n", subcommand)
		printDaemonHelp()
		os.Exit(1)
	}
}

func runDaemonStart() {
	// Parse arguments
	interval := 3600
	logDir := getLogDir()

	for i := 3; i < len(os.Args); i++ {
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

	// Validate interval
	if interval < 10 {
		fmt.Fprintf(os.Stderr, "Error: Minimum interval is 10 seconds\n")
		os.Exit(1)
	}
	if interval > 86400 {
		fmt.Fprintf(os.Stderr, "Error: Maximum interval is 86400 seconds (24 hours)\n")
		os.Exit(1)
	}

	manager := monitoring.NewMonitoringManager(logDir)
	result := manager.Start(interval)

	if !result.Success {
		fmt.Fprintf(os.Stderr, "Error: %s\n", result.Error)
		os.Exit(1)
	}

	fmt.Printf("✓ Monitoring daemon started successfully\n")
	fmt.Printf("  PID: %d\n", result.PID)
	fmt.Printf("  Interval: %d seconds\n", result.IntervalSeconds)
	fmt.Printf("  Log directory: %s\n", result.LogDir)
	fmt.Println("\nDaemon will continue running in background even if you close this terminal.")
	fmt.Println("Use 'chihuaudit daemon status' to check status.")
	fmt.Println("Use 'chihuaudit daemon stop' to stop monitoring.")
}

func runDaemonStop() {
	logDir := getLogDir()
	manager := monitoring.NewMonitoringManager(logDir)
	result := manager.Stop()

	if !result.Success {
		fmt.Fprintf(os.Stderr, "Error: %s\n", result.Error)
		os.Exit(1)
	}

	fmt.Printf("✓ %s\n", result.Message)
}

func runDaemonStatus() {
	logDir := getLogDir()
	manager := monitoring.NewMonitoringManager(logDir)
	status := manager.GetStatus()

	if status.Running {
		fmt.Printf("✓ Monitoring daemon is running\n")
		fmt.Printf("  PID: %d\n", status.PID)
	} else {
		fmt.Println("✗ Monitoring daemon is not running")
	}

	fmt.Printf("  Log directory: %s\n", status.LogDir)
	fmt.Printf("  Baseline exists: %v\n", status.BaselineExists)
	fmt.Printf("  Bulletins collected: %d\n", status.BulletinCount)
	fmt.Printf("  Anomalies detected: %d\n", status.AnomalyCount)
	fmt.Printf("  Disk usage: %d KB\n", status.TotalDiskUsageKB)
}

func printDaemonHelp() {
	help := `chihuaudit daemon - Manage monitoring daemon lifecycle

USAGE:
    chihuaudit daemon <SUBCOMMAND>

SUBCOMMANDS:
    start       Start monitoring daemon in background
    stop        Stop monitoring daemon
    status      Show daemon status and statistics

START OPTIONS:
    --interval, -i SECONDS   Check interval (default: 3600, min: 10, max: 86400)
    --log-dir, -d PATH       Log directory

EXAMPLES:
    # Start daemon with 1 hour interval
    sudo chihuaudit daemon start

    # Start with 5 minute interval
    sudo chihuaudit daemon start --interval 300

    # Check status
    sudo chihuaudit daemon status

    # Stop daemon
    sudo chihuaudit daemon stop

NOTE:
    The daemon process is fully detached and will continue running even if you:
    - Close the terminal
    - Logout from SSH
    - Close Claude Desktop
    - Restart your local machine (server keeps running)
`
	fmt.Print(help)
}

func getLogDir() string {
	if os.Geteuid() == 0 {
		return "/var/log/chihuaudit"
	}
	return fmt.Sprintf("/tmp/chihuaudit-%d", os.Getuid())
}

func printHelp() {
	help := `chihuaudit - MCP-based Linux Cybersecurity Tool

USAGE:
    chihuaudit [COMMAND]

COMMANDS:
    (none)          Run as MCP server (default)
    audit           Run security audit with standardized output (recommended)
    baseline        Manage configuration baselines (create/diff/verify)
    whitelist       Manage alert code whitelist (add/remove/list)
    serve           Start MCP server with pre-loaded data (NO sudo required)
    test            Run one-time security audit (legacy JSON output)
    verify          Verify prerequisites and configuration
    daemon          Manage monitoring daemon (start/stop/status) - RECOMMENDED
    monitor         Start continuous monitoring (foreground mode)
    monitor-once    Run single monitoring check
    monitor-status  Show monitoring daemon status
    version         Show version information
    help            Show this help message

AUDIT OPTIONS (chihuaudit audit):
    --format=FORMAT   Output format: text, json, summary, compact
    --quiet, -q       Suppress output (return exit code only)
    --ai              Enable AI mode (includes recommendations)
    --webhook         Send webhook notification
    --on-issues       Only output/notify when issues are found

    Exit codes: 0=OK (green), 1=WARNING (yellow), 2=CRITICAL (red)

DAEMON OPTIONS (chihuaudit daemon start):
    --interval, -i SECONDS   Check interval (default: 3600, min: 10, max: 86400)
    --log-dir, -d PATH       Log directory

MONITOR OPTIONS (foreground mode):
    --interval, -i SECONDS   Check interval (default: 3600, min: 300)
    --log-dir, -d PATH       Log directory

EXAMPLES:
    # Run as MCP server (for Claude Desktop - requires sudo)
    chihuaudit

    # Create baseline (known-good state)
    sudo chihuaudit baseline create

    # Check for configuration drifts
    sudo chihuaudit baseline diff

    # PRIVILEGE SEPARATION: Audit + Serve (RECOMMENDED for security)
    sudo chihuaudit audit --format=json --output /tmp/audit.json
    chihuaudit serve --input /tmp/audit.json  # No sudo!

    # Pipe mode (real-time privilege separation)
    sudo chihuaudit audit --format=json | chihuaudit serve

    # Run security audit with visual output
    sudo chihuaudit audit

    # Cron job: notify via webhook only when issues found
    sudo chihuaudit audit --quiet --webhook --on-issues

    # Get JSON output for scripts
    sudo chihuaudit audit --format=json

    # One-line summary for monitoring dashboards
    sudo chihuaudit audit --format=summary

    # Start monitoring daemon (detached, survives terminal close)
    sudo chihuaudit daemon start

    # Start daemon with custom interval (5 minutes)
    sudo chihuaudit daemon start --interval 300

    # Check daemon status
    sudo chihuaudit daemon status

    # Stop daemon
    sudo chihuaudit daemon stop

CONFIGURATION:
    Config file locations (in order of priority):
    - .chihuaudit.yaml (current directory)
    - ~/.chihuaudit.yaml (home directory)
    - /etc/chihuaudit/config.yaml (system-wide)

For more information, visit: https://github.com/girste/chihuaudit
`
	fmt.Print(help)
}

func runBaseline() {
	if len(os.Args) < 3 {
		printBaselineHelp()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "create":
		runBaselineCreate()
	case "diff":
		runBaselineDiff()
	case "verify":
		runBaselineVerify()
	case "update":
		runBaselineUpdate()
	case "help", "--help", "-h":
		printBaselineHelp()
	default:
		fmt.Printf("Unknown baseline subcommand: %s\n", subcommand)
		printBaselineHelp()
		os.Exit(1)
	}
}

func runBaselineCreate() {
	fmt.Println("Creating baseline snapshot...")

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	orchestrator := audit.NewOrchestrator()
	ctx := context.Background()

	// Run audit to collect current state
	auditResults, err := orchestrator.RunAudit(ctx, cfg, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to collect system state: %v\n", err)
		os.Exit(1)
	}

	// Create baseline
	bl, err := baseline.Create(auditResults, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create baseline: %v\n", err)
		os.Exit(1)
	}

	// Get baseline path
	baselinePath, err := baseline.GetDefaultPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get baseline path: %v\n", err)
		os.Exit(1)
	}

	// Save baseline
	if err := baseline.Save(bl, baselinePath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save baseline: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Baseline created successfully\n")
	fmt.Printf("  Path: %s\n", baselinePath)
	fmt.Printf("  Timestamp: %s\n", bl.Metadata.Timestamp)
	fmt.Printf("  Hostname: %s\n", bl.Metadata.Hostname)
	fmt.Printf("  Signature: %s\n", bl.Signature[:20]+"...")
	fmt.Println("\nBaseline represents the current 'known-good' state of your system.")
	fmt.Println("Use 'chihuaudit baseline diff' to detect configuration drifts.")
}

func runBaselineDiff() {
	// Parse flags
	formatType := "text"
	outputFile := ""

	for i := 3; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case strings.HasPrefix(arg, "--format="):
			formatType = strings.TrimPrefix(arg, "--format=")
		case arg == "--format" && i+1 < len(os.Args):
			formatType = os.Args[i+1]
			i++
		case strings.HasPrefix(arg, "--output="):
			outputFile = strings.TrimPrefix(arg, "--output=")
		case arg == "--output" && i+1 < len(os.Args):
			outputFile = os.Args[i+1]
			i++
		}
	}

	fmt.Println("Comparing current state against baseline...")

	// Load baseline
	baselinePath, err := baseline.GetDefaultPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get baseline path: %v\n", err)
		os.Exit(1)
	}

	bl, err := baseline.Load(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load baseline: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nHint: Create a baseline first with 'chihuaudit baseline create'\n")
		os.Exit(1)
	}

	// Run current audit
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	orchestrator := audit.NewOrchestrator()
	ctx := context.Background()

	currentResults, err := orchestrator.RunAudit(ctx, cfg, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to collect current state: %v\n", err)
		os.Exit(1)
	}

	// Compare
	diffResult, err := baseline.Compare(bl, currentResults)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to compare baseline: %v\n", err)
		os.Exit(1)
	}

	// Generate alerts
	alerts := alertcodes.GenerateAlerts(diffResult.Drifts)

	// Format output
	var output string
	if formatType == "json" {
		data, _ := json.MarshalIndent(alerts, "", "  ")
		output = string(data)
	} else if formatType == "yaml" {
		data, _ := yaml.Marshal(alerts)
		output = string(data)
	} else {
		// Text format
		output = formatDriftText(diffResult, alerts)
	}

	// Write output
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(output), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write output: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Drift report written to: %s\n", outputFile)
	} else {
		fmt.Print(output)
	}

	// Exit code: 0 if no drifts, 1 if drifts detected
	if diffResult.DriftCount > 0 {
		os.Exit(1)
	}
}

func formatDriftText(diffResult *baseline.DiffResult, alerts []alertcodes.Alert) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\nBaseline Comparison Report\n"))
	sb.WriteString(fmt.Sprintf("==========================\n\n"))
	sb.WriteString(fmt.Sprintf("Baseline timestamp: %s\n", diffResult.BaselineTimestamp))
	sb.WriteString(fmt.Sprintf("Current timestamp:  %s\n", diffResult.CurrentTimestamp))
	sb.WriteString(fmt.Sprintf("Drifts detected:    %d\n\n", diffResult.DriftCount))

	if diffResult.DriftCount == 0 {
		sb.WriteString("✓ No configuration drifts detected. System matches baseline.\n")
		return sb.String()
	}

	sb.WriteString("Configuration Drifts:\n")
	sb.WriteString("--------------------\n\n")

	for _, alert := range alerts {
		// Color based on severity
		severitySymbol := "•"
		switch alert.Severity {
		case "critical":
			severitySymbol = "🔴"
		case "high":
			severitySymbol = "🟠"
		case "medium":
			severitySymbol = "🟡"
		case "low":
			severitySymbol = "🔵"
		}

		sb.WriteString(fmt.Sprintf("%s [%s] %s: %s\n", severitySymbol, alert.Code, strings.ToUpper(string(alert.Severity)), alert.Message))
		sb.WriteString(fmt.Sprintf("   Analyzer: %s | Field: %s | Change: %s\n", alert.Analyzer, alert.Field, alert.ChangeType))

		if alert.Before != nil {
			sb.WriteString(fmt.Sprintf("   Before: %v\n", alert.Before))
		}
		if alert.After != nil {
			sb.WriteString(fmt.Sprintf("   After:  %v\n", alert.After))
		}
		if alert.Recommendation != "" {
			sb.WriteString(fmt.Sprintf("   → %s\n", alert.Recommendation))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("\n⚠️  Review these changes and verify they were authorized.\n")
	sb.WriteString("   Use whitelist to suppress known-good changes.\n")

	return sb.String()
}

func runBaselineVerify() {
	baselinePath, err := baseline.GetDefaultPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get baseline path: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Verifying baseline signature: %s\n", baselinePath)

	bl, err := baseline.Load(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Baseline signature is valid\n")
	fmt.Printf("  Timestamp: %s\n", bl.Metadata.Timestamp)
	fmt.Printf("  Hostname: %s\n", bl.Metadata.Hostname)
	fmt.Printf("  Version: %s\n", bl.Metadata.Version)
	fmt.Printf("  Signature: %s\n", bl.Signature)
}

func runBaselineUpdate() {
	baselinePath, err := baseline.GetDefaultPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get baseline path: %v\n", err)
		os.Exit(1)
	}

	// Check if baseline exists
	if _, err := os.Stat(baselinePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "✗ No existing baseline found at %s\n", baselinePath)
		fmt.Fprintf(os.Stderr, "  Run 'chihuaudit baseline create' to create initial baseline\n")
		os.Exit(1)
	}

	// Create backup of old baseline
	timestamp := time.Now().Unix()
	backupPath := fmt.Sprintf("%s.backup-%d", baselinePath, timestamp)
	
	fmt.Printf("Updating baseline: %s\n", baselinePath)
	fmt.Printf("Creating backup: %s\n", backupPath)

	// Copy old baseline to backup
	input, err := os.ReadFile(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to read existing baseline: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(backupPath, input, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to create backup: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Backup created\n")

	// Create new baseline (reuse runBaselineCreate logic)
	fmt.Println("\nRunning audit to create new baseline...")

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	orchestrator := audit.NewOrchestrator()
	ctx := context.Background()

	// Run audit to collect current state
	auditResults, err := orchestrator.RunAudit(ctx, cfg, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to collect system state: %v\n", err)
		os.Exit(1)
	}

	// Create baseline
	bl, err := baseline.Create(auditResults, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create baseline: %v\n", err)
		os.Exit(1)
	}

	if err := baseline.Save(bl, baselinePath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save baseline: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ Baseline updated successfully\n")
	fmt.Printf("  New baseline: %s\n", baselinePath)
	fmt.Printf("  Old backup: %s\n", backupPath)
	fmt.Printf("  Signature: %s\n", bl.Signature[:20]+"...")
}

func printBaselineHelp() {
	help := `chihuaudit baseline - Manage system configuration baselines

USAGE:
    chihuaudit baseline <SUBCOMMAND>

SUBCOMMANDS:
    create      Create a new baseline snapshot (signed)
    diff        Compare current state against baseline
    verify      Verify baseline signature integrity
    update      Update baseline (backup old + create new)

DIFF OPTIONS:
    --format=FORMAT    Output format: text, json, yaml (default: text)
    --output=FILE      Write diff report to file

EXIT CODES (diff):
    0    No drifts detected (system matches baseline)
    1    Configuration drifts detected

EXAMPLES:
    # Create initial baseline (after configuring system correctly)
    sudo chihuaudit baseline create

    # Check for configuration drifts
    sudo chihuaudit baseline diff

    # Get JSON diff for automation
    sudo chihuaudit baseline diff --format=json

    # Verify baseline hasn't been tampered with
    chihuaudit baseline verify

    # Update baseline after authorized changes
    sudo chihuaudit baseline update

WORKFLOW:
    1. Configure your system to a known-good, secure state
    2. Create baseline: sudo chihuaudit baseline create
    3. Periodically check for drifts: sudo chihuaudit baseline diff
    4. Review alerts and verify changes were authorized
    5. Update baseline when making intentional changes

BASELINE FILE:
    Location: ~/.chihuaudit/baseline.yaml
    Format: YAML with cryptographic signature (SHA256)
    Protection: Signature prevents tampering

ALERT CODES:
    FW-XXX    Firewall configuration changes
    SSH-XXX   SSH daemon configuration changes
    SVC-XXX   Services and listening ports changes
    USR-XXX   User accounts and permissions changes
    DOC-XXX   Docker configuration changes
    (and more...)
`
	fmt.Print(help)
}

func runWhitelist() {
if len(os.Args) < 3 {
printWhitelistHelp()
os.Exit(1)
}

subcommand := os.Args[2]
switch subcommand {
case "add":
runWhitelistAdd()
case "remove":
runWhitelistRemove()
case "list":
runWhitelistList()
case "help", "--help", "-h":
printWhitelistHelp()
default:
fmt.Printf("Unknown whitelist subcommand: %s\n", subcommand)
printWhitelistHelp()
os.Exit(1)
}
}

func runWhitelistAdd() {
if len(os.Args) < 4 {
fmt.Println("Error: Alert code required")
fmt.Println("Usage: chihuaudit whitelist add <ALERT_CODE>")
os.Exit(1)
}

alertCode := os.Args[3]

// Load or create whitelist
whitelistPath := getWhitelistPath()
wl := loadOrCreateWhitelist(whitelistPath)

// Add alert code
if wl.IsAlertWhitelisted(alertCode) {
fmt.Printf("Alert code %s is already whitelisted\n", alertCode)
return
}

wl.AddAlertCode(alertCode)

// Save whitelist
if err := saveWhitelist(wl, whitelistPath); err != nil {
fmt.Fprintf(os.Stderr, "Failed to save whitelist: %v\n", err)
os.Exit(1)
}

fmt.Printf("✓ Alert code %s added to whitelist\n", alertCode)
fmt.Printf("  File: %s\n", whitelistPath)
}

func runWhitelistRemove() {
if len(os.Args) < 4 {
fmt.Println("Error: Alert code required")
fmt.Println("Usage: chihuaudit whitelist remove <ALERT_CODE>")
os.Exit(1)
}

alertCode := os.Args[3]

whitelistPath := getWhitelistPath()
wl := loadOrCreateWhitelist(whitelistPath)

if wl.RemoveAlertCode(alertCode) {
if err := saveWhitelist(wl, whitelistPath); err != nil {
fmt.Fprintf(os.Stderr, "Failed to save whitelist: %v\n", err)
os.Exit(1)
}
fmt.Printf("✓ Alert code %s removed from whitelist\n", alertCode)
} else {
fmt.Printf("Alert code %s not found in whitelist\n", alertCode)
os.Exit(1)
}
}

func runWhitelistList() {
whitelistPath := getWhitelistPath()
wl := loadOrCreateWhitelist(whitelistPath)

codes := wl.GetWhitelistedAlertCodes()

if len(codes) == 0 {
fmt.Println("No alert codes whitelisted")
fmt.Printf("  File: %s\n", whitelistPath)
return
}

fmt.Printf("Whitelisted Alert Codes (%d):\n", len(codes))
fmt.Println("──────────────────────────────")
for _, code := range codes {
fmt.Printf("  %s\n", code)
}
fmt.Printf("\nWhitelist file: %s\n", whitelistPath)
}

func getWhitelistPath() string {
// Check current directory first
if _, err := os.Stat(".chihuaudit-whitelist.yaml"); err == nil {
return ".chihuaudit-whitelist.yaml"
}

// Check home directory
homeDir, err := os.UserHomeDir()
if err == nil {
homePath := filepath.Join(homeDir, ".chihuaudit-whitelist.yaml")
if _, err := os.Stat(homePath); err == nil {
return homePath
}
}

// Default to current directory
return ".chihuaudit-whitelist.yaml"
}

func loadOrCreateWhitelist(path string) *config.Whitelist {
data, err := os.ReadFile(path)
if err != nil {
// Create new whitelist
return &config.Whitelist{
Version:    "1.0",
AlertCodes: []string{},
}
}

var wl config.Whitelist
if err := yaml.Unmarshal(data, &wl); err != nil {
fmt.Fprintf(os.Stderr, "Failed to parse whitelist: %v\n", err)
os.Exit(1)
}

return &wl
}

func saveWhitelist(wl *config.Whitelist, path string) error {
data, err := yaml.Marshal(wl)
if err != nil {
return err
}

return os.WriteFile(path, data, 0600)
}

func printWhitelistHelp() {
help := `chihuaudit whitelist - Manage alert code whitelist

USAGE:
    chihuaudit whitelist <SUBCOMMAND>

SUBCOMMANDS:
    add <CODE>      Add alert code to whitelist
    remove <CODE>   Remove alert code from whitelist
    list            List all whitelisted alert codes

EXAMPLES:
    # Whitelist a known-good drift
    chihuaudit whitelist add FW-001

    # Remove from whitelist
    chihuaudit whitelist remove FW-001

    # List all whitelisted codes
    chihuaudit whitelist list

ALERT CODES:
    FW-XXX     Firewall configuration changes
    SSH-XXX    SSH daemon configuration changes
    SVC-XXX    Services and listening ports changes
    USR-XXX    User accounts and permissions changes
    DOC-XXX    Docker configuration changes
    F2B-XXX    Fail2ban configuration changes
    UPD-XXX    System updates changes
    KRN-XXX    Kernel parameters changes
    DSK-XXX    Disk configuration changes
    MAC-XXX    MAC (AppArmor/SELinux) changes
    SSL-XXX    SSL/TLS certificate changes
    THR-XXX    Threat detection changes
    CVE-XXX    CVE/vulnerability changes

WHITELIST FILE:
    Location: .chihuaudit-whitelist.yaml (current dir or ~/.chihuaudit-whitelist.yaml)
    Format: YAML

    Example content:
    version: "1.0"
    alertCodes:
      - "SVC-012"  # Dev server on port 8080
      - "FW-003"   # Expected firewall rule change

WORKFLOW:
    1. Run baseline diff and review alerts
    2. For legitimate changes, add alert code to whitelist
    3. Future occurrences of whitelisted codes will be suppressed
    4. Update baseline when configuration intentionally changes
`
fmt.Print(help)
}
