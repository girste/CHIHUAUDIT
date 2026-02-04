package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/girste/chihuaudit/internal/audit"
	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/notify"
	"github.com/girste/chihuaudit/internal/output"
)

// RunAudit executes the audit command
func RunAudit() int {
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
			PrintAuditHelp()
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
				Title:     fmt.Sprintf("Security Audit: %s", report.TrafficLight.Label),
				Summary:   fmt.Sprintf("Score: %d/100 (%s) - %d issues found", report.Score.Value, report.Score.Grade, len(report.Negatives)),
				Issues:    issues,
				Positives: report.Positives,
			}

			notifier.Send(context.Background(), alert)
		}
	}

	// Generate output
	if !quiet {
		var outputStr string
		var err error

		switch formatType {
		case "json":
			outputStr, err = formatter.ToJSON(report, false)
		case "summary":
			outputStr = formatter.ToSummary(report)
		case "compact":
			outputStr = formatter.ToSummary(report)
		default:
			outputStr = formatter.ToText(report)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to format output: %v\n", err)
			return 2
		}

		if outputFile != "" {
			if err := os.WriteFile(outputFile, []byte(outputStr), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write output file: %v\n", err)
				return 2
			}
		} else {
			fmt.Println(outputStr)
		}
	}

	return exitCode
}

// PrintAuditHelp displays help for the audit command
func PrintAuditHelp() {
	help := `chihuaudit audit - Run security audit

USAGE:
    chihuaudit audit [OPTIONS]

OPTIONS:
    --format=FORMAT   Output format: text, json, summary, compact (default: text)
    --output=FILE     Write output to file instead of stdout
    --quiet, -q       Suppress output (return exit code only)
    --ai              Enable AI mode (includes recommendations)
    --webhook         Send webhook notification
    --on-issues       Only output/notify when issues are found
    --help, -h        Show this help message

EXIT CODES:
    0  OK (green) - No issues found
    1  WARNING (yellow) - Some issues found
    2  CRITICAL (red) - Critical issues found or error

EXAMPLES:
    chihuaudit audit
    chihuaudit audit --format=json --output=report.json
    chihuaudit audit --quiet --webhook
    chihuaudit audit --ai --on-issues
`
	fmt.Print(help)
}
