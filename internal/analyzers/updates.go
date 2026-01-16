package analyzers

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/girste/mcp-cybersec-watchdog/internal/config"
	"github.com/girste/mcp-cybersec-watchdog/internal/system"
)

type UpdatesAnalyzer struct{}

func (a *UpdatesAnalyzer) Name() string           { return "updates" }
func (a *UpdatesAnalyzer) RequiresSudo() bool     { return true }
func (a *UpdatesAnalyzer) Timeout() time.Duration { return system.TimeoutVeryLong }

func (a *UpdatesAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	distro := system.GetDistro(ctx)

	if system.IsDebian(distro) {
		return a.analyzeDebian(ctx, result)
	} else if system.IsRHEL(distro) {
		return a.analyzeRHEL(ctx, result)
	}

	result.Checked = false
	return result, nil
}

func (a *UpdatesAnalyzer) analyzeDebian(ctx context.Context, result *Result) (*Result, error) {
	// Update package list (can be slow)
	updateResult, _ := system.RunCommandSudo(ctx, system.TimeoutVeryLong, "apt-get", "update", "-qq")
	if updateResult == nil || !updateResult.Success {
		result.Checked = false
		return result, nil
	}

	// Get upgradable packages
	listResult, _ := system.RunCommand(ctx, system.TimeoutMedium, "apt", "list", "--upgradable")
	if listResult == nil || !listResult.Success {
		result.Checked = false
		return result, nil
	}

	totalUpdates := 0
	securityUpdates := 0
	securityPackages := []string{}

	for _, line := range strings.Split(listResult.Stdout, "\n") {
		if strings.Contains(line, "[upgradable") {
			totalUpdates++
			if strings.Contains(line, "-security") {
				securityUpdates++
				// Extract package name
				parts := strings.Fields(line)
				if len(parts) > 0 {
					securityPackages = append(securityPackages, parts[0])
				}
			}
		}
	}

	result.Data = map[string]interface{}{
		"totalUpdates":     totalUpdates,
		"securityUpdates":  securityUpdates,
		"securityPackages": securityPackages,
	}

	a.addUpdateIssues(result, totalUpdates, securityUpdates)

	return result, nil
}

func (a *UpdatesAnalyzer) analyzeRHEL(ctx context.Context, result *Result) (*Result, error) {
	// Check for updates
	checkResult, _ := system.RunCommandSudo(ctx, system.TimeoutVeryLong, "yum", "check-update", "--security")

	// yum check-update returns 100 if updates available, 0 if none
	totalUpdates := 0
	securityUpdates := 0

	if checkResult != nil {
		lines := strings.Split(checkResult.Stdout, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Loaded") || strings.HasPrefix(line, "Last") {
				continue
			}
			// Lines with package updates
			if strings.Contains(line, ".") && !strings.HasPrefix(line, "#") {
				totalUpdates++
				securityUpdates++ // yum check-update --security only shows security updates
			}
		}
	}

	result.Data = map[string]interface{}{
		"totalUpdates":    totalUpdates,
		"securityUpdates": securityUpdates,
	}

	a.addUpdateIssues(result, totalUpdates, securityUpdates)

	return result, nil
}

func (a *UpdatesAnalyzer) addUpdateIssues(result *Result, total, security int) {
	if security > 10 {
		result.AddIssue(NewIssue(SeverityCritical, strconv.Itoa(security)+" critical security updates available", "Apply security updates immediately"))
	} else if security > 0 {
		result.AddIssue(NewIssue(SeverityHigh, strconv.Itoa(security)+" security updates available", "Apply security updates soon"))
	}

	if total > 50 {
		result.AddIssue(NewIssue(SeverityMedium, strconv.Itoa(total)+" total updates available", "Keep system up to date"))
	}
}
