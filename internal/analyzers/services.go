package analyzers

import (
	"bufio"
	"context"
	"encoding/hex"
	"os"
	"regexp"
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

// readListeningPorts reads /proc/net/tcp and /proc/net/tcp6 from host to find listening ports
func readListeningPorts(ctx context.Context) ([]map[string]interface{}, []int) {
	exposedServices := []map[string]interface{}{}
	listeningPorts := []int{}

	// In container with network namespace separation, we need nsenter to access host network
	// Try reading via nsenter first, fallback to direct file access
	hostExec := system.GetHostExecutor()

	// Read IPv4 TCP via nsenter
	tcp4Result, err := hostExec.RunHostCommand(ctx, system.TimeoutShort, "cat", "/proc/net/tcp")
	var tcp4Data string
	if err == nil && tcp4Result != nil && tcp4Result.Success {
		tcp4Data = tcp4Result.Stdout
	} else {
		// Fallback: direct file read (works in some container configurations)
		tcp4Path := system.HostPath("/proc/net/tcp")
		if data, err := os.ReadFile(tcp4Path); err == nil {
			tcp4Data = string(data)
		}
	}

	if tcp4Data != "" {
		scanner := bufio.NewScanner(strings.NewReader(tcp4Data))
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
				"process": "unknown",
			})
		}
	}

	// Read IPv6 TCP via nsenter
	tcp6Result, err := hostExec.RunHostCommand(ctx, system.TimeoutShort, "cat", "/proc/net/tcp6")
	var tcp6Data string
	if err == nil && tcp6Result != nil && tcp6Result.Success {
		tcp6Data = tcp6Result.Stdout
	} else {
		// Fallback: direct file read
		tcp6Path := system.HostPath("/proc/net/tcp6")
		if data, err := os.ReadFile(tcp6Path); err == nil {
			tcp6Data = string(data)
		}
	}

	if tcp6Data != "" {
		scanner := bufio.NewScanner(strings.NewReader(tcp6Data))
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

	// Read listening ports from host /proc/net/tcp and /proc/net/tcp6
	_, listeningPorts := readListeningPorts(ctx)

	// Auto-discovery: Enrich ports with process information via ss/netstat
	enrichedDetails := enrichPortsWithProcessInfo(ctx, listeningPorts)

	// Update exposedServices with enriched data
	enrichedServices := make([]map[string]interface{}, 0, len(enrichedDetails))
	for _, detail := range enrichedDetails {
		enrichedServices = append(enrichedServices, map[string]interface{}{
			"port":    detail.Port,
			"bind":    detail.Bind,
			"process": detail.Process,
			"pid":     detail.PID,
			"risk":    detail.Risk,
		})
	}

	// Failed services check via HostExecutor
	failedCount := 0
	hostExec := system.GetHostExecutor()
	failedResult, err := hostExec.RunHostCommand(ctx, system.TimeoutShort, "systemctl", "list-units", "--failed", "--no-pager")
	if err == nil && failedResult != nil && failedResult.Success {
		for _, line := range strings.Split(failedResult.Stdout, "\n") {
			if strings.Contains(line, "failed") && strings.Contains(line, ".service") {
				failedCount++
			}
		}
	}

	result.Data = map[string]interface{}{
		"exposedServices": enrichedServices,
		"exposedCount":    len(enrichedServices),
		"listeningPorts":  listeningPorts,
		"failedUnits":     failedCount,
	}

	// Add issues
	if failedCount > 0 {
		result.AddIssue(NewIssue(SeverityHigh, strconv.Itoa(failedCount)+" systemd units in failed state", "Check and fix failed services"))
	}

	// Check for risky services on exposed ports (using centralized patterns)
	for _, detail := range enrichedDetails {
		// Skip localhost bindings (127.0.0.1, ::1)
		if detail.Bind == "127.0.0.1" || detail.Bind == "::1" {
			continue
		}

		// Check if it's a risky database port
		if service, isRisky := cfg.Ports.GetRiskyService(detail.Port); isRisky {
			// Auto-discovery: Check if process matches database pattern
			if cfg.Processes.IsDatabaseProcess(detail.Process) {
				// Check whitelist before reporting
				if cfg.Whitelist != nil {
					if cfg.Whitelist.IsServiceWhitelisted(detail.Port, detail.Bind) {
						continue // Whitelisted, skip
					}
					if (detail.Bind == "0.0.0.0" || detail.Bind == "::") && cfg.Whitelist.IsWildcardPortAllowed(detail.Port) {
						continue // Whitelisted wildcard port, skip
					}
				}
				result.AddIssue(NewIssue(SeverityMedium, service+" ("+detail.Process+") is exposed on "+detail.Bind+":"+strconv.Itoa(detail.Port), "Ensure database is not accessible from internet"))
			}
			continue
		}

		// Context-aware: Web server ports on wildcard binding
		if cfg.Ports.IsWebPort(detail.Port) {
			// Auto-discovery: Check if process matches web server patterns
			if cfg.Processes.IsWebServerProcess(detail.Process) {
				continue // Known web server on web port - expected, skip
			}
			// Unknown process on web port - report as info only if we identified the process
			if detail.Process != "unknown" {
				result.AddIssue(NewIssue(SeverityLow, "Port "+strconv.Itoa(detail.Port)+" exposed on "+detail.Bind+" by process: "+detail.Process, "Verify this is an intentional web server"))
			}
		}

		// Wildcard bindings with high risk (not web, not database patterns)
		if detail.Risk == "high" && detail.Process != "unknown" {
			// Skip if it's a known safe process (web server, proxy)
			if !cfg.Processes.IsWebServerProcess(detail.Process) && !cfg.Processes.IsDatabaseProcess(detail.Process) {
				// Report custom service exposed on wildcard
				result.AddIssue(NewIssue(SeverityLow, "Service "+detail.Process+" listening on "+detail.Bind+":"+strconv.Itoa(detail.Port), "Verify if this service needs network exposure"))
			}
		}
	}

	return result, nil
}

// enrichPortsWithProcessInfo uses ss/netstat to correlate ports with processes
func enrichPortsWithProcessInfo(ctx context.Context, ports []int) []portDetail {
	if len(ports) == 0 {
		return []portDetail{}
	}

	// Use ss command (modern, faster)
	if system.CommandExists("ss") {
		return enrichWithSS(ctx, ports)
	}

	// Fallback to netstat (older systems)
	if system.CommandExists("netstat") {
		return enrichWithNetstat(ctx, ports)
	}

	// No tools available - return basic info
	return createBasicPortDetails(ports)
}

// portDetail contains enriched port information
type portDetail struct {
	Port    int
	Process string
	PID     int
	Bind    string
	Risk    string
}

// enrichWithSS uses ss command
func enrichWithSS(ctx context.Context, ports []int) []portDetail {
	result, err := system.RunCommandSudo(ctx, system.TimeoutShort, "ss", "-tlnp")
	if err != nil || result == nil || !result.Success {
		return createBasicPortDetails(ports)
	}

	portMap := make(map[int]portDetail)
	ssAddrRegex := regexp.MustCompile(`([\d\.]+|\[\:[\:a-f0-9]*\]|\*):(\d+)`)
	ssProcRegex := regexp.MustCompile(`users:\(\("([^"]+)",pid=(\d+)`)

	for _, line := range strings.Split(result.Stdout, "\n") {
		if strings.HasPrefix(line, "State") || strings.TrimSpace(line) == "" {
			continue
		}

		matches := ssAddrRegex.FindStringSubmatch(line)
		if len(matches) < 3 {
			continue
		}

		portNum, err := strconv.Atoi(matches[2])
		if err != nil {
			continue
		}

		// Check if this is one of our target ports
		found := false
		for _, p := range ports {
			if p == portNum {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		bindAddr := normalizeBindAddr(matches[1])
		detail := portDetail{
			Port:    portNum,
			Bind:    bindAddr,
			Process: "unknown",
			PID:     0,
			Risk:    determinePortRisk(bindAddr),
		}

		// Extract process info
		procMatches := ssProcRegex.FindStringSubmatch(line)
		if len(procMatches) >= 3 {
			detail.Process = procMatches[1]
			if pid, err := strconv.Atoi(procMatches[2]); err == nil {
				detail.PID = pid
			}
		}

		portMap[portNum] = detail
	}

	return buildOrderedPortResults(ports, portMap)
}

// enrichWithNetstat uses netstat command
func enrichWithNetstat(ctx context.Context, ports []int) []portDetail {
	result, err := system.RunCommandSudo(ctx, system.TimeoutShort, "netstat", "-tlnp")
	if err != nil || result == nil || !result.Success {
		return createBasicPortDetails(ports)
	}

	portMap := make(map[int]portDetail)
	netstatRegex := regexp.MustCompile(`^(tcp|tcp6)\s+\d+\s+\d+\s+([\d\.:]+|\*):(\d+)\s+.*?(\d+)/(\S+)`)

	for _, line := range strings.Split(result.Stdout, "\n") {
		matches := netstatRegex.FindStringSubmatch(line)
		if len(matches) < 6 {
			continue
		}

		portNum, err := strconv.Atoi(matches[3])
		if err != nil {
			continue
		}

		found := false
		for _, p := range ports {
			if p == portNum {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		pid, _ := strconv.Atoi(matches[4])
		bindAddr := normalizeBindAddr(matches[2])
		detail := portDetail{
			Port:    portNum,
			Bind:    bindAddr,
			Process: matches[5],
			PID:     pid,
			Risk:    determinePortRisk(bindAddr),
		}

		portMap[portNum] = detail
	}

	return buildOrderedPortResults(ports, portMap)
}

func normalizeBindAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "*" {
		return "0.0.0.0"
	}
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		addr = strings.Trim(addr, "[]")
	}
	if addr == "::1" {
		return "127.0.0.1"
	}
	return addr
}

func determinePortRisk(bindAddr string) string {
	if bindAddr == "0.0.0.0" || bindAddr == "::" {
		return "high"
	}
	if bindAddr == "127.0.0.1" || bindAddr == "::1" || strings.HasPrefix(bindAddr, "127.") {
		return "low"
	}
	return "medium"
}

func createBasicPortDetails(ports []int) []portDetail {
	details := make([]portDetail, len(ports))
	for i, port := range ports {
		details[i] = portDetail{
			Port:    port,
			Process: "unknown",
			PID:     0,
			Bind:    "unknown",
			Risk:    "medium",
		}
	}
	return details
}

func buildOrderedPortResults(ports []int, portMap map[int]portDetail) []portDetail {
	results := make([]portDetail, len(ports))
	for i, port := range ports {
		if detail, found := portMap[port]; found {
			results[i] = detail
		} else {
			results[i] = portDetail{
				Port:    port,
				Process: "unknown",
				PID:     0,
				Bind:    "unknown",
				Risk:    "medium",
			}
		}
	}
	return results
}
