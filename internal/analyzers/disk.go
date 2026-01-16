package analyzers

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/girste/mcp-cybersec-watchdog/internal/config"
	"github.com/girste/mcp-cybersec-watchdog/internal/system"
)

type DiskAnalyzer struct{}

func (a *DiskAnalyzer) Name() string           { return "disk" }
func (a *DiskAnalyzer) RequiresSudo() bool     { return false }
func (a *DiskAnalyzer) Timeout() time.Duration { return system.TimeoutShort }

func (a *DiskAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	dfResult, _ := system.RunCommand(ctx, system.TimeoutShort, "df", "-h")
	if dfResult == nil || !dfResult.Success {
		result.Checked = false
		return result, nil
	}

	criticalCount := 0
	warningCount := 0

	for _, line := range strings.Split(dfResult.Stdout, "\n") {
		if !strings.Contains(line, "%") {
			continue
		}

		// Extract percentage
		percentRegex := regexp.MustCompile(`(\d+)%`)
		match := percentRegex.FindStringSubmatch(line)
		if len(match) < 2 {
			continue
		}

		percent, _ := strconv.Atoi(match[1])

		if percent > 90 {
			criticalCount++
		} else if percent > 80 {
			warningCount++
		}
	}

	result.Data = map[string]interface{}{
		"criticalCount": criticalCount,
		"warningCount":  warningCount,
	}

	if criticalCount > 0 {
		result.AddIssue(NewIssue(SeverityCritical, strconv.Itoa(criticalCount)+" filesystems critically low on space (>90%)", "Free up disk space immediately"))
	} else if warningCount > 0 {
		result.AddIssue(NewIssue(SeverityMedium, strconv.Itoa(warningCount)+" filesystems low on space (>80%)", "Monitor disk usage"))
	}

	return result, nil
}
