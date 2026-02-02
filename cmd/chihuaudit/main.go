package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/girste/chihuaudit/internal/audit"
	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/mcp"
	"github.com/girste/chihuaudit/internal/monitoring"
	"github.com/girste/chihuaudit/internal/notify"
	"github.com/girste/chihuaudit/internal/output"
	"github.com/girste/chihuaudit/internal/system"
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

		case "monitor":
			runMonitor()
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
