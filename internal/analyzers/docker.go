package analyzers

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/girste/mcp-cybersec-watchdog/internal/config"
	"github.com/girste/mcp-cybersec-watchdog/internal/system"
)

type DockerAnalyzer struct{}

func (a *DockerAnalyzer) Name() string           { return "docker" }
func (a *DockerAnalyzer) RequiresSudo() bool     { return false }
func (a *DockerAnalyzer) Timeout() time.Duration { return system.TimeoutMedium }

func (a *DockerAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	if !system.CommandExists("docker") {
		installed := false
		result.SetInstalled(installed)
		result.Checked = true
		return result, nil
	}

	installed := true
	result.SetInstalled(installed)

	// Get running containers
	psResult, _ := system.RunCommand(ctx, system.TimeoutShort, "docker", "ps", "-q")
	if psResult == nil || !psResult.Success {
		result.Checked = false
		return result, nil
	}

	containerIDs := strings.Fields(psResult.Stdout)
	runningCount := len(containerIDs)

	// Check if rootless
	infoResult, _ := system.RunCommand(ctx, system.TimeoutShort, "docker", "info", "--format", "{{.SecurityOptions}}")
	rootless := false
	if infoResult != nil && infoResult.Success {
		rootless = strings.Contains(infoResult.Stdout, "rootless")
	}

	// Count privileged containers
	privilegedCount := 0
	for _, id := range containerIDs {
		inspectResult, _ := system.RunCommand(ctx, system.TimeoutShort, "docker", "inspect", "--format", "{{.HostConfig.Privileged}}", id)
		if inspectResult != nil && inspectResult.Success && strings.TrimSpace(inspectResult.Stdout) == "true" {
			privilegedCount++
		}
	}

	result.Data = map[string]interface{}{
		"runningContainers": runningCount,
		"rootless":          rootless,
		"privilegedCount":   privilegedCount,
	}

	// Add issues
	if privilegedCount > 0 {
		result.AddIssue(NewIssue(SeverityHigh, "Privileged containers detected: "+strconv.Itoa(privilegedCount), "Avoid running containers in privileged mode"))
	}

	if !rootless && runningCount > 0 {
		result.AddIssue(NewIssue(SeverityMedium, "Docker is not running in rootless mode", "Consider enabling rootless mode for better security"))
	}

	if runningCount > 20 {
		result.AddIssue(NewIssue(SeverityLow, "Many containers running: "+strconv.Itoa(runningCount), "Large attack surface, ensure all are necessary"))
	}

	return result, nil
}
