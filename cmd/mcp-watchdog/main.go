package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/girste/mcp-cybersec-watchdog/internal/audit"
	"github.com/girste/mcp-cybersec-watchdog/internal/config"
	"github.com/girste/mcp-cybersec-watchdog/internal/mcp"
	"github.com/girste/mcp-cybersec-watchdog/internal/monitoring"
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
    test            Run one-time security audit
    verify          Verify prerequisites and configuration
    monitor         Start continuous monitoring daemon
    monitor-once    Run single monitoring check
    monitor-status  Show monitoring daemon status
    version         Show version information
    help            Show this help message

MONITOR OPTIONS:
    --interval, -i SECONDS   Check interval (default: 3600, min: 300)
    --log-dir, -d PATH       Log directory

EXAMPLES:
    # Run as MCP server (for Claude Desktop)
    mcp-watchdog

    # Run standalone audit
    sudo mcp-watchdog test

    # Check prerequisites
    mcp-watchdog verify

    # Start continuous monitoring (1 hour interval)
    sudo mcp-watchdog monitor

    # Start monitoring with 5 minute interval
    sudo mcp-watchdog monitor --interval 300

    # Run single monitoring check
    sudo mcp-watchdog monitor-once

CONFIGURATION:
    Config file locations (in order of priority):
    - .mcp-watchdog.yaml (current directory)
    - ~/.mcp-watchdog.yaml (home directory)
    - /etc/mcp-watchdog/config.yaml (system-wide)

For more information, visit: https://github.com/girste/mcp-cybersec-watchdog
`
	fmt.Print(help)
}
