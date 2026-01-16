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

type ServicesAnalyzer struct{}

func (a *ServicesAnalyzer) Name() string           { return "services" }
func (a *ServicesAnalyzer) RequiresSudo() bool     { return true }
func (a *ServicesAnalyzer) Timeout() time.Duration { return system.TimeoutMedium }

func (a *ServicesAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	// Get listening ports with ss
	ssResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "ss", "-tulpn")
	if ssResult == nil || !ssResult.Success {
		result.Checked = false
		return result, nil
	}

	exposedServices := []map[string]interface{}{}
	listeningPorts := []int{}

	// Parse ss output
	for _, line := range strings.Split(ssResult.Stdout, "\n") {
		if !strings.Contains(line, "LISTEN") && !strings.Contains(line, "UNCONN") {
			continue
		}

		// Extract local address and port
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		localAddr := fields[4]

		// Parse address:port
		parts := strings.Split(localAddr, ":")
		if len(parts) < 2 {
			continue
		}

		portStr := parts[len(parts)-1]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		listeningPorts = append(listeningPorts, port)

		// Extract process info if available
		process := "unknown"
		if len(fields) > 6 {
			processField := fields[6]
			if strings.Contains(processField, "\"") {
				processRegex := regexp.MustCompile(`"([^"]+)"`)
				if match := processRegex.FindStringSubmatch(processField); len(match) > 1 {
					process = match[1]
				}
			}
		}

		exposedServices = append(exposedServices, map[string]interface{}{
			"port":    port,
			"process": process,
		})
	}

	// Check for failed services
	failedResult, _ := system.RunCommand(ctx, system.TimeoutShort, "systemctl", "list-units", "--failed", "--no-pager")
	failedCount := 0
	if failedResult != nil && failedResult.Success {
		for _, line := range strings.Split(failedResult.Stdout, "\n") {
			if strings.Contains(line, "failed") {
				failedCount++
			}
		}
	}

	result.Data = map[string]interface{}{
		"exposedServices": exposedServices,
		"exposedCount":    len(exposedServices),
		"listeningPorts":  listeningPorts,
		"failedUnits":     failedCount,
	}

	// Add issues
	if failedCount > 0 {
		result.AddIssue(NewIssue(SeverityHigh, strconv.Itoa(failedCount)+" systemd units in failed state", "Check and fix failed services"))
	}

	// Check for risky services on exposed ports
	riskyPorts := map[int]string{
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
	}

	for port, service := range riskyPorts {
		for _, p := range listeningPorts {
			if p == port {
				result.AddIssue(NewIssue(SeverityMedium, service+" is exposed on port "+strconv.Itoa(port), "Ensure database is not accessible from internet"))
				break
			}
		}
	}

	return result, nil
}
