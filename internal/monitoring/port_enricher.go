package monitoring

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/girste/chihuaudit/internal/system"
)

// PortDetail contains enriched information about a listening port
type PortDetail struct {
	Port    int    `json:"port"`
	Process string `json:"process"`
	PID     int    `json:"pid"`
	Bind    string `json:"bind"` // "127.0.0.1", "0.0.0.0", "::", etc.
	Risk    string `json:"risk"` // "low" (localhost) or "high" (wildcard)
}

var (
	// Regex to parse ss output: "127.0.0.1:8080" or "0.0.0.0:80" or "[::]:443" or "[::1]:8080"
	ssAddrRegex = regexp.MustCompile(`([\d\.]+|\[\:[\:a-f0-9]*\]|\*):(\d+)`)
	// Regex to parse process info: users:(("nginx",pid=1234,fd=6))
	ssProcRegex = regexp.MustCompile(`users:\(\("([^"]+)",pid=(\d+)`)
	// Regex for netstat output (fallback)
	netstatRegex = regexp.MustCompile(`^(tcp|tcp6)\s+\d+\s+\d+\s+([\d\.:]+|\*):(\d+)\s+.*?(\d+)/(\S+)`)
)

// EnrichPortDetails enriches a list of ports with process and binding information
// Uses ss command (preferred) with fallback to netstat if unavailable
func EnrichPortDetails(ctx context.Context, ports []int) []PortDetail {
	if len(ports) == 0 {
		return []PortDetail{}
	}

	// Try ss first (modern, faster)
	if system.CommandExists("ss") {
		return enrichWithSS(ctx, ports)
	}

	// Fallback to netstat (older systems, BSD/macOS)
	if system.CommandExists("netstat") {
		return enrichWithNetstat(ctx, ports)
	}

	// No tools available - return basic info
	return createBasicDetails(ports)
}

// enrichWithSS uses ss command to get port details
func enrichWithSS(ctx context.Context, ports []int) []PortDetail {
	// Execute: ss -tlnp (tcp, listening, numeric, process info)
	result, err := system.RunCommand(ctx, system.TimeoutShort, "ss", "-tlnp")
	if err != nil || result == nil || !result.Success {
		return createBasicDetails(ports)
	}

	// Parse output
	portMap := make(map[int]PortDetail)
	for _, line := range strings.Split(result.Stdout, "\n") {
		// Skip header and empty lines
		if strings.HasPrefix(line, "State") || strings.TrimSpace(line) == "" {
			continue
		}

		// Extract port from address (e.g., "127.0.0.1:8080" -> 8080)
		matches := ssAddrRegex.FindStringSubmatch(line)
		if len(matches) < 3 {
			continue
		}

		portNum, err := strconv.Atoi(matches[2])
		if err != nil {
			continue
		}

		// Check if this is one of our target ports
		if !contains(ports, portNum) {
			continue
		}

		detail := PortDetail{
			Port:    portNum,
			Bind:    normalizeBindAddr(matches[1]),
			Process: "unknown",
			PID:     0,
		}

		// Extract process info: users:(("nginx",pid=1234,fd=6))
		procMatches := ssProcRegex.FindStringSubmatch(line)
		if len(procMatches) >= 3 {
			detail.Process = procMatches[1]
			if pid, err := strconv.Atoi(procMatches[2]); err == nil {
				detail.PID = pid
			}
		}

		// Determine risk based on bind address
		detail.Risk = determineRisk(detail.Bind)

		portMap[portNum] = detail
	}

	// Return in original order, fill missing with basic info
	return buildOrderedResults(ports, portMap)
}

// enrichWithNetstat uses netstat command as fallback
func enrichWithNetstat(ctx context.Context, ports []int) []PortDetail {
	// Execute: netstat -tlnp (tcp, listening, numeric, program)
	// Note: -p requires root on some systems
	result, err := system.RunCommandSudo(ctx, system.TimeoutShort, "netstat", "-tlnp")
	if err != nil || result == nil || !result.Success {
		return createBasicDetails(ports)
	}

	portMap := make(map[int]PortDetail)
	for _, line := range strings.Split(result.Stdout, "\n") {
		matches := netstatRegex.FindStringSubmatch(line)
		if len(matches) < 6 {
			continue
		}

		portNum, err := strconv.Atoi(matches[3])
		if err != nil || !contains(ports, portNum) {
			continue
		}

		pid, _ := strconv.Atoi(matches[4])
		detail := PortDetail{
			Port:    portNum,
			Bind:    normalizeBindAddr(matches[2]),
			Process: matches[5],
			PID:     pid,
			Risk:    determineRisk(normalizeBindAddr(matches[2])),
		}

		portMap[portNum] = detail
	}

	return buildOrderedResults(ports, portMap)
}

// FormatEnrichedMessage formats port details into a human-readable message
func FormatEnrichedMessage(details []PortDetail) string {
	if len(details) == 0 {
		return "New services listening (details unavailable)"
	}

	var parts []string
	for _, d := range details {
		var msg string
		if d.Process != "unknown" && d.PID > 0 {
			msg = fmt.Sprintf("Port %d: %s/%d (%s)", d.Port, d.Process, d.PID, formatBindAddress(d.Bind, d.Risk))
		} else if d.Process != "unknown" {
			msg = fmt.Sprintf("Port %d: %s (%s)", d.Port, d.Process, formatBindAddress(d.Bind, d.Risk))
		} else {
			msg = fmt.Sprintf("Port %d (%s)", d.Port, formatBindAddress(d.Bind, d.Risk))
		}
		parts = append(parts, msg)
	}

	return strings.Join(parts, " - ")
}

// Helper functions

func buildPortPattern(ports []int) string {
	portStrs := make([]string, len(ports))
	for i, p := range ports {
		portStrs[i] = strconv.Itoa(p)
	}
	return fmt.Sprintf(":(%s)", strings.Join(portStrs, "|"))
}

func normalizeBindAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	// Normalize asterisk to 0.0.0.0
	if addr == "*" {
		return "0.0.0.0"
	}
	// Extract IP from bracketed notation [::] or [::1]
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		addr = strings.Trim(addr, "[]")
	}
	// ::1 is IPv6 localhost - normalize to 127.0.0.1 for consistency
	if addr == "::1" {
		return "127.0.0.1"
	}
	// Keep :: (IPv6 wildcard) and 0.0.0.0 (IPv4 wildcard) separate
	return addr
}

func determineRisk(bindAddr string) string {
	// Wildcard bindings (0.0.0.0, ::) are exposed to network
	if bindAddr == "0.0.0.0" || bindAddr == "::" {
		return "high"
	}
	// Localhost bindings are safe
	if bindAddr == "127.0.0.1" || bindAddr == "::1" || strings.HasPrefix(bindAddr, "127.") {
		return "low"
	}
	// Specific IP binding - medium risk
	return "medium"
}

func formatBindAddress(bind, risk string) string {
	switch risk {
	case "low":
		return "localhost ✓"
	case "high":
		if bind == "0.0.0.0" || bind == "::" {
			return bind + " ⚠️ EXPOSED"
		}
		return bind + " ⚠️"
	default:
		return bind
	}
}

func contains(slice []int, item int) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func createBasicDetails(ports []int) []PortDetail {
	details := make([]PortDetail, len(ports))
	for i, port := range ports {
		details[i] = PortDetail{
			Port:    port,
			Process: "unknown",
			PID:     0,
			Bind:    "unknown",
			Risk:    "medium",
		}
	}
	return details
}

func buildOrderedResults(ports []int, portMap map[int]PortDetail) []PortDetail {
	results := make([]PortDetail, len(ports))
	for i, port := range ports {
		if detail, found := portMap[port]; found {
			results[i] = detail
		} else {
			// Port not found in output - create basic entry
			results[i] = PortDetail{
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
