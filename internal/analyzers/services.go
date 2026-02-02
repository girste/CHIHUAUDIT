package analyzers

import (
	"bufio"
	"context"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
)

type ServicesAnalyzer struct{}

func (a *ServicesAnalyzer) Name() string           { return "services" }
func (a *ServicesAnalyzer) RequiresSudo() bool     { return true }
func (a *ServicesAnalyzer) Timeout() time.Duration { return system.TimeoutMedium }

// parseHexPort converts hex port from /proc/net/tcp to decimal
func parseHexPort(hexPort string) (int, error) {
	decoded, err := hex.DecodeString(hexPort)
	if err != nil {
		return 0, err
	}
	if len(decoded) != 2 {
		return 0, strconv.ErrRange
	}
	// Big-endian
	port := int(decoded[0])*256 + int(decoded[1])
	return port, nil
}

// parseHexIP converts hex IP from /proc/net/tcp to string
func parseHexIP(hexIP string, isIPv6 bool) string {
	if !isIPv6 {
		// IPv4: Little-endian 4 bytes
		decoded, err := hex.DecodeString(hexIP)
		if err != nil || len(decoded) != 4 {
			return "0.0.0.0"
		}
		return strconv.Itoa(int(decoded[3])) + "." + strconv.Itoa(int(decoded[2])) + "." + strconv.Itoa(int(decoded[1])) + "." + strconv.Itoa(int(decoded[0]))
	}
	// IPv6: Complex, return :: for now (most common is ::)
	if hexIP == "00000000000000000000000000000000" {
		return "::"
	}
	if hexIP == "00000000000000000000000001000000" {
		return "::1"
	}
	return "::" // Simplified, full IPv6 parsing is complex
}

// readListeningPorts reads /proc/net/tcp and /proc/net/tcp6 to find listening ports
func readListeningPorts() ([]map[string]interface{}, []int) {
	exposedServices := []map[string]interface{}{}
	listeningPorts := []int{}
	
	// Read IPv4 TCP
	tcp4Path := system.HostPath("/proc/net/tcp")
	if data, err := os.ReadFile(tcp4Path); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		scanner.Scan() // Skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			// Check state: 0A = LISTEN (10 in decimal)
			state := fields[3]
			if state != "0A" {
				continue
			}
			
			// Parse local_address (format: IP:PORT in hex)
			localAddrParts := strings.Split(fields[1], ":")
			if len(localAddrParts) != 2 {
				continue
			}
			
			port, err := parseHexPort(localAddrParts[1])
			if err != nil {
				continue
			}
			bindIP := parseHexIP(localAddrParts[0], false)
			
			listeningPorts = append(listeningPorts, port)
			exposedServices = append(exposedServices, map[string]interface{}{
				"port":    port,
				"bind":    bindIP,
				"process": "unknown", // We could read /proc/net/tcp inode and match to /proc/*/fd/* but complex
			})
		}
	}
	
	// Read IPv6 TCP
	tcp6Path := system.HostPath("/proc/net/tcp6")
	if data, err := os.ReadFile(tcp6Path); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		scanner.Scan() // Skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			state := fields[3]
			if state != "0A" {
				continue
			}
			
			localAddrParts := strings.Split(fields[1], ":")
			if len(localAddrParts) != 2 {
				continue
			}
			
			port, err := parseHexPort(localAddrParts[1])
			if err != nil {
				continue
			}
			bindIP := parseHexIP(localAddrParts[0], true)
			
			// Check if port already added (avoid duplicates)
			exists := false
			for _, existing := range listeningPorts {
				if existing == port {
					exists = true
					break
				}
			}
			if !exists {
				listeningPorts = append(listeningPorts, port)
				exposedServices = append(exposedServices, map[string]interface{}{
					"port":    port,
					"bind":    bindIP,
					"process": "unknown",
				})
			}
		}
	}
	
	return exposedServices, listeningPorts
}

func (a *ServicesAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	// Read listening ports from /proc/net/tcp and /proc/net/tcp6
	exposedServices, listeningPorts := readListeningPorts()

	// Failed services check - only if systemctl available (gracefully skip in container)
	failedCount := 0
	if system.CommandExists("systemctl") {
		failedResult, _ := system.RunCommand(ctx, system.TimeoutShort, "systemctl", "list-units", "--failed", "--no-pager")
		if failedResult != nil && failedResult.Success {
			for _, line := range strings.Split(failedResult.Stdout, "\n") {
				if strings.Contains(line, "failed") && strings.Contains(line, ".service") {
					failedCount++
				}
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

		// Skip localhost bindings (127.0.0.1, ::1)
		if bindAddr == "127.0.0.1" || bindAddr == "::1" {
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
