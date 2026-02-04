package commands

import (
	"fmt"

	"github.com/girste/chihuaudit/internal/util"
)

// PrintHelp displays the main help message
func PrintHelp() {
	help := `chihuaudit - Docker-only Linux Cybersecurity Tool

USAGE:
    chihuaudit [COMMAND]

COMMANDS:
    (none)      Start MCP server (default)
    audit       Run security audit
    monitor     Continuous monitoring (use --once for single check)
    baseline    Manage configuration baselines
    whitelist   Manage alert code whitelist  
    serve       Start MCP server with pre-loaded data
    verify      Verify prerequisites
    version     Show version
    help        This help

AUDIT OPTIONS (chihuaudit audit):
    --format=FORMAT   Output format: text, json, summary, compact
    --quiet, -q       Suppress output (return exit code only)
    --ai              Enable AI mode (includes recommendations)
    --webhook         Send webhook notification
    --on-issues       Only output/notify when issues are found

    Exit codes: 0=OK (green), 1=WARNING (yellow), 2=CRITICAL (red)

MONITOR OPTIONS:
    --interval, -i SECONDS   Check interval (default: 3600)
    --log-dir, -d PATH       Log directory
    --once                   Run single check and exit

EXAMPLES:
    # Run as MCP server (default, requires sudo)
    chihuaudit

    # Create baseline (known-good state)
    sudo chihuaudit baseline create

    # Check for configuration drifts
    sudo chihuaudit baseline diff

    # PRIVILEGE SEPARATION (RECOMMENDED)
    sudo chihuaudit audit --format=json --output /tmp/audit.json
    chihuaudit serve --input /tmp/audit.json  # No sudo!

    # Run security audit with visual output
    sudo chihuaudit audit

    # Cron job: notify via webhook only when issues found
    sudo chihuaudit audit --quiet --webhook --on-issues

    # Continuous monitoring (foreground)
    sudo chihuaudit monitor

    # Single monitoring check
    sudo chihuaudit monitor --once

DOCKER USAGE:
    Docker is the recommended deployment method. Use Docker restart
    policies for daemon management instead of built-in daemon commands.

    docker run -d --restart=unless-stopped \\
      --privileged \\
      -v /var/run/docker.sock:/var/run/docker.sock \\
      ghcr.io/girste/chihuaudit:latest

CONFIGURATION:
    Config file locations (in order of priority):
    - .chihuaudit.yaml (current directory)
    - ~/.chihuaudit.yaml (home directory)
    - /etc/chihuaudit/config.yaml (system-wide)

For more information, visit: https://github.com/girste/chihuaudit
`
	fmt.Print(help)
}

// PrintVersion displays version information
func PrintVersion() {
	fmt.Printf("chihuaudit version %s\n", util.Version)
}
