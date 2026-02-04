package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/alertcodes"
	"github.com/girste/chihuaudit/internal/audit"
	"github.com/girste/chihuaudit/internal/baseline"
	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/output"
	"github.com/girste/chihuaudit/internal/util"
	"gopkg.in/yaml.v3"
)

// RunBaseline handles the baseline command
func RunBaseline() {
	if len(os.Args) < 3 {
		PrintBaselineHelp()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "create":
		RunBaselineCreate()
	case "diff":
		RunBaselineDiff()
	case "verify":
		RunBaselineVerify()
	case "update":
		RunBaselineUpdate()
	case "help", "--help", "-h":
		PrintBaselineHelp()
	default:
		fmt.Printf("Unknown baseline subcommand: %s\n", subcommand)
		PrintBaselineHelp()
		os.Exit(1)
	}
}

// RunBaselineCreate creates a new baseline snapshot
func RunBaselineCreate() {
	fmt.Println("Creating baseline snapshot...")

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	orchestrator := audit.NewOrchestrator()
	ctx := context.Background()

	auditResults, err := orchestrator.RunAudit(ctx, cfg, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to collect system state: %v\n", err)
		os.Exit(1)
	}

	bl, err := baseline.Create(auditResults, util.Version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create baseline: %v\n", err)
		os.Exit(1)
	}

	baselinePath, err := baseline.GetDefaultPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get baseline path: %v\n", err)
		os.Exit(1)
	}

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

// RunBaselineDiff compares current state against baseline
func RunBaselineDiff() {
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

	diffResult, err := baseline.Compare(bl, currentResults)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to compare baseline: %v\n", err)
		os.Exit(1)
	}

	riskMap := config.DefaultAnalyzerRiskMap()
	alerts := alertcodes.GenerateAlerts(diffResult.Drifts, riskMap)

	var outputStr string
	switch formatType {
	case "json":
		data, _ := json.MarshalIndent(alerts, "", "  ")
		outputStr = string(data)
	case "yaml":
		data, _ := yaml.Marshal(alerts)
		outputStr = string(data)
	default:
		outputStr = output.FormatDriftText(diffResult, alerts)
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(outputStr), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write output: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Drift report written to: %s\n", outputFile)
	} else {
		fmt.Print(outputStr)
	}

	if diffResult.DriftCount > 0 {
		os.Exit(1)
	}
}

// RunBaselineVerify verifies baseline signature integrity
func RunBaselineVerify() {
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

// RunBaselineUpdate updates baseline with backup
func RunBaselineUpdate() {
	baselinePath, err := baseline.GetDefaultPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get baseline path: %v\n", err)
		os.Exit(1)
	}

	if _, err := os.Stat(baselinePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "✗ No existing baseline found at %s\n", baselinePath)
		fmt.Fprintf(os.Stderr, "  Run 'chihuaudit baseline create' to create initial baseline\n")
		os.Exit(1)
	}

	timestamp := time.Now().Unix()
	backupPath := fmt.Sprintf("%s.backup-%d", baselinePath, timestamp)

	fmt.Printf("Updating baseline: %s\n", baselinePath)
	fmt.Printf("Creating backup: %s\n", backupPath)

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
	fmt.Println("\nRunning audit to create new baseline...")

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	orchestrator := audit.NewOrchestrator()
	ctx := context.Background()

	auditResults, err := orchestrator.RunAudit(ctx, cfg, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to collect system state: %v\n", err)
		os.Exit(1)
	}

	bl, err := baseline.Create(auditResults, util.Version)
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

// PrintBaselineHelp displays help for baseline command
func PrintBaselineHelp() {
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
