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

// isLocalhostBinding checks if the bind address is localhost-only
func isLocalhostBinding(addr string) bool {
	return addr == "127.0.0.1" || addr == "::1" || addr == "localhost" || addr == ""
}

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

		// Parse address:port, handling both IPv4 and IPv6 formats
		// IPv4: 127.0.0.1:5432 or 0.0.0.0:5432
		// IPv6: [::1]:5432 or [::]:5432 or :::5432
		var bindAddr string
		var portStr string

		if strings.HasPrefix(localAddr, "[") {
			// IPv6 with brackets: [::1]:5432
			closeBracket := strings.Index(localAddr, "]")
			if closeBracket != -1 {
				bindAddr = localAddr[1:closeBracket]
				remainingParts := strings.Split(localAddr[closeBracket+1:], ":")
				if len(remainingParts) > 1 {
					portStr = remainingParts[1]
				}
			}
		} else {
			// IPv4 or IPv6 without brackets
			parts := strings.Split(localAddr, ":")
			if len(parts) >= 2 {
				portStr = parts[len(parts)-1]
				bindAddr = strings.Join(parts[:len(parts)-1], ":")
			}
		}

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
			"bind":    bindAddr,
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

	// Check for risky services on exposed ports (using centralized patterns)
	for _, svc := range exposedServices {
		svcPort, ok := svc["port"].(int)
		if !ok {
			continue
		}

		bindAddr, _ := svc["bind"].(string)
		processName, _ := svc["process"].(string)

		// Skip localhost bindings (always safe)
		if isLocalhostBinding(bindAddr) {
			continue
		}

		// Check if it's a risky database port
		if service, isRisky := cfg.Ports.GetRiskyService(svcPort); isRisky {
			// Check whitelist before reporting
			if cfg.Whitelist != nil {
				if cfg.Whitelist.IsServiceWhitelisted(svcPort, bindAddr) {
					continue // Whitelisted, skip
				}
				if (bindAddr == "0.0.0.0" || bindAddr == "::") && cfg.Whitelist.IsWildcardPortAllowed(svcPort) {
					continue // Whitelisted wildcard port, skip
				}
			}
			result.AddIssue(NewIssue(SeverityMedium, service+" is exposed on "+bindAddr+":"+strconv.Itoa(svcPort), "Ensure database is not accessible from internet (currently bound to "+bindAddr+")"))
			continue
		}

		// Context-aware: Web server ports on wildcard binding
		if cfg.Ports.IsWebPort(svcPort) {
			// Auto-discovery: Check if process matches web server patterns
			if cfg.Processes.IsWebServerProcess(processName) {
				continue // Known web server on web port - expected, skip
			}
			// Unknown process on web port - report as low severity
			result.AddIssue(NewIssue(SeverityLow, "Port "+strconv.Itoa(svcPort)+" exposed on "+bindAddr+" by unknown process: "+processName, "Verify this is an intentional web server. Known patterns are auto-detected."))
		}
	}

	return result, nil
}
