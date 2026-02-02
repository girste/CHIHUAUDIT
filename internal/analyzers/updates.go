package analyzers

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
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
	// Check last update time by reading apt lists timestamp
	listsPath := system.HostPath("/var/lib/apt/lists")
	lastUpdateTime := time.Time{}
	
	if entries, err := os.ReadDir(listsPath); err == nil {
		for _, entry := range entries {
			if strings.Contains(entry.Name(), "Packages") {
				fullPath := filepath.Join(listsPath, entry.Name())
				if info, err := os.Stat(fullPath); err == nil {
					if info.ModTime().After(lastUpdateTime) {
						lastUpdateTime = info.ModTime()
					}
				}
			}
		}
	}

	daysSinceUpdate := 999
	if !lastUpdateTime.IsZero() {
		daysSinceUpdate = int(time.Since(lastUpdateTime).Hours() / 24)
	}
	
	// Try to get updates count - fallback to apt command if available
	totalUpdates := 0
	securityUpdates := 0
	securityPackages := []string{}
	
	if system.CommandExists("apt") {
		listResult, _ := system.RunCommand(ctx, system.TimeoutMedium, "apt", "list", "--upgradable")
		if listResult != nil && listResult.Success {
			for _, line := range strings.Split(listResult.Stdout, "\n") {
				if strings.Contains(line, "[upgradable") {
					totalUpdates++
					if strings.Contains(line, "-security") {
						securityUpdates++
						parts := strings.Fields(line)
						if len(parts) > 0 {
							securityPackages = append(securityPackages, parts[0])
						}
					}
				}
			}
		}
	}

	result.Data = map[string]interface{}{
		"totalUpdates":     totalUpdates,
		"securityUpdates":  securityUpdates,
		"securityPackages": securityPackages,
		"daysSinceUpdate":  daysSinceUpdate,
	}

	a.addUpdateIssues(result, totalUpdates, securityUpdates)
	
	// Warn if updates are very old
	if daysSinceUpdate > 30 {
		result.AddIssue(NewIssue(SeverityMedium, "Package lists not updated in "+strconv.Itoa(daysSinceUpdate)+" days", "Run apt-get update regularly"))
	}

	return result, nil
}

func (a *UpdatesAnalyzer) analyzeRHEL(ctx context.Context, result *Result) (*Result, error) {
	// Check last update by reading yum/dnf cache timestamp
	cachePaths := []string{
		system.HostPath("/var/cache/dnf"),
		system.HostPath("/var/cache/yum"),
	}
	
	lastUpdateTime := time.Time{}
	for _, cachePath := range cachePaths {
		if info, err := os.Stat(cachePath); err == nil {
			if info.ModTime().After(lastUpdateTime) {
				lastUpdateTime = info.ModTime()
			}
		}
	}
	
	daysSinceUpdate := 999
	if !lastUpdateTime.IsZero() {
		daysSinceUpdate = int(time.Since(lastUpdateTime).Hours() / 24)
	}

	// Try yum/dnf commands if available
	totalUpdates := 0
	securityUpdates := 0
	
	if system.CommandExists("dnf") {
		checkResult, _ := system.RunCommand(ctx, system.TimeoutVeryLong, "dnf", "check-update", "--security", "-q")
		if checkResult != nil {
			for _, line := range strings.Split(checkResult.Stdout, "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "Last") && strings.Contains(line, ".") {
					totalUpdates++
					securityUpdates++
				}
			}
		}
	} else if system.CommandExists("yum") {
		checkResult, _ := system.RunCommandSudo(ctx, system.TimeoutVeryLong, "yum", "check-update", "--security")
		if checkResult != nil {
			for _, line := range strings.Split(checkResult.Stdout, "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "Loaded") && !strings.HasPrefix(line, "Last") && strings.Contains(line, ".") && !strings.HasPrefix(line, "#") {
					totalUpdates++
					securityUpdates++
				}
			}
		}
	}

	result.Data = map[string]interface{}{
		"totalUpdates":    totalUpdates,
		"securityUpdates": securityUpdates,
		"daysSinceUpdate": daysSinceUpdate,
	}

	a.addUpdateIssues(result, totalUpdates, securityUpdates)
	
	// Warn if updates are very old
	if daysSinceUpdate > 30 {
		result.AddIssue(NewIssue(SeverityMedium, "Package cache not updated in "+strconv.Itoa(daysSinceUpdate)+" days", "Run yum/dnf check-update regularly"))
	}

	return result, nil
}

func (a *UpdatesAnalyzer) addUpdateIssues(result *Result, total, security int) {
	if security > 10 {
		result.AddIssue(NewIssue(SeverityCritical, strconv.Itoa(security)+" security updates pending", "apt upgrade"))
	} else if security > 0 {
		result.AddIssue(NewIssue(SeverityHigh, strconv.Itoa(security)+" security updates pending", "apt upgrade"))
	}

	if total > 50 {
		result.AddIssue(NewIssue(SeverityMedium, strconv.Itoa(total)+" updates pending", "apt upgrade"))
	}
}
