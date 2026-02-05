package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"chihuaudit/checks"
	"chihuaudit/config"
	"chihuaudit/notify"
	"chihuaudit/report"
	"chihuaudit/state"
)

func main() {
	auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)
	auditJSON := auditCmd.Bool("json", false, "Output in JSON format")

	monitorCmd := flag.NewFlagSet("monitor", flag.ExitOnError)
	monitorInterval := monitorCmd.String("interval", "5m", "Monitoring interval (e.g., 5m, 10m, 1h)")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "audit":
		_ = auditCmd.Parse(os.Args[2:])
		runAudit(*auditJSON)

	case "monitor":
		_ = monitorCmd.Parse(os.Args[2:])
		interval, err := time.ParseDuration(*monitorInterval)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid interval: %v\n", err)
			os.Exit(1)
		}
		runMonitor(interval)

	case "init-config":
		initConfig()

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("chihuaudit - Universal system auditing tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  chihuaudit audit [--json]         Run single audit")
	fmt.Println("  chihuaudit monitor [--interval]   Start monitoring mode")
	fmt.Println("  chihuaudit init-config            Generate default config file")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  chihuaudit audit                  Single audit, text output")
	fmt.Println("  chihuaudit audit --json           Single audit, JSON output")
	fmt.Println("  chihuaudit monitor                Monitor with 5m interval")
	fmt.Println("  chihuaudit monitor --interval=10m Monitor with custom interval")
	fmt.Println("  chihuaudit init-config            Create ~/.chihuaudit/config.json")
}

func initConfig() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting home directory: %v\n", err)
		os.Exit(1)
	}

	configDir := filepath.Join(homeDir, ".chihuaudit")
	configPath := filepath.Join(configDir, "config.json")

	// Check if already exists
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("Config already exists at: %s\n", configPath)
		fmt.Println("Edit it manually or delete it first.")
		return
	}

	// Create directory
	if err := os.MkdirAll(configDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating config directory: %v\n", err)
		os.Exit(1)
	}

	// Default config
	defaultConfig := `{
  "discord_webhook": "",
  "notification_whitelist": {
    "cpu_threshold": 60,
    "memory_threshold": 60,
    "disk_threshold": 80,
    "ignore_changes": [
      "uptime",
      "active_connections",
      "process_list",
      "network_rx_tx"
    ]
  }
}
`

	// Write config
	if err := os.WriteFile(configPath, []byte(defaultConfig), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Created default config at: %s\n", configPath)
	fmt.Println()
	fmt.Println("To enable Discord notifications:")
	fmt.Printf("  1. Edit: %s\n", configPath)
	fmt.Println("  2. Add your Discord webhook URL")
	fmt.Println("  3. Adjust thresholds as needed")
}

func runAudit(jsonOutput bool) {
	results := checks.RunAll()

	if jsonOutput {
		report.PrintJSON(results)
	} else {
		report.PrintText(results)
	}
}

func runMonitor(interval time.Duration) {
	cfg := config.Load()

	fmt.Printf("Starting monitoring (interval: %v)\n", interval)
	if cfg.DiscordWebhook != "" {
		fmt.Println("Discord notifications: enabled")
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Load previous state if exists
	previous := state.Load()
	if previous == nil {
		// Initial audit
		fmt.Printf("[%s] Running initial audit...\n", time.Now().Format("15:04:05"))
		previous = checks.RunAll()
		report.PrintText(previous)
		_ = state.Save(previous)
	} else {
		fmt.Printf("[%s] Loaded previous state from %s\n", time.Now().Format("15:04:05"), previous.Timestamp.Format("2006-01-02 15:04:05"))
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Printf("[%s] Checking for changes...\n", time.Now().Format("15:04:05"))

		current := checks.RunAll()
		changes := state.Compare(previous, current, cfg)

		if len(changes) == 0 {
			fmt.Println("No changes detected")
		} else {
			fmt.Printf("%d changes detected:\n", len(changes))
			for _, change := range changes {
				fmt.Printf("  - %s\n", change.Description)
				state.Log(change)

				if change.ShouldNotify {
					notify.SendDiscord(cfg, change)
					fmt.Println("    → Discord notification sent")
				}
			}
		}

		_ = state.Save(current)
		previous = current
		fmt.Println()
	}
}
