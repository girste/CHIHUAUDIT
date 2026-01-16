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

type FirewallAnalyzer struct{}

func (a *FirewallAnalyzer) Name() string           { return "firewall" }
func (a *FirewallAnalyzer) RequiresSudo() bool     { return true }
func (a *FirewallAnalyzer) Timeout() time.Duration { return system.TimeoutMedium }

func (a *FirewallAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	// Try UFW first
	if fwType, fwData := a.analyzeUFW(ctx); fwType != "" {
		result.Data = fwData
		a.addFirewallIssues(result, fwData)
		return result, nil
	}

	// Try Firewalld
	if fwType, fwData := a.analyzeFirewalld(ctx); fwType != "" {
		result.Data = fwData
		a.addFirewallIssues(result, fwData)
		return result, nil
	}

	// Try iptables
	if fwType, fwData := a.analyzeIptables(ctx); fwType != "" {
		result.Data = fwData
		a.addFirewallIssues(result, fwData)
		return result, nil
	}

	// No firewall detected
	result.Data = map[string]interface{}{
		"type":   "none",
		"active": false,
	}
	result.AddIssue(NewIssue(SeverityCritical, "No firewall detected", "Install and configure ufw, firewalld, or iptables"))

	return result, nil
}

func (a *FirewallAnalyzer) analyzeUFW(ctx context.Context) (string, map[string]interface{}) {
	if !system.CommandExists("ufw") {
		return "", nil
	}

	result, err := system.RunCommandSudo(ctx, system.TimeoutShort, "ufw", "status", "verbose")
	if err != nil || result == nil || !result.Success {
		return "", nil
	}

	data := make(map[string]interface{})
	data["type"] = "ufw"

	active := strings.Contains(strings.ToLower(result.Stdout), "status: active")
	data["active"] = active

	// Extract default policy
	defaultPolicy := "unknown"
	if match := regexp.MustCompile(`Default: deny \(incoming\)`).FindString(result.Stdout); match != "" {
		defaultPolicy = "deny"
	} else if match := regexp.MustCompile(`Default: allow \(incoming\)`).FindString(result.Stdout); match != "" {
		defaultPolicy = "allow"
	}
	data["defaultPolicy"] = defaultPolicy

	// Count rules
	rulesCount := 0
	for _, line := range strings.Split(result.Stdout, "\n") {
		if strings.Contains(line, "ALLOW") || strings.Contains(line, "DENY") {
			rulesCount++
		}
	}
	data["rulesCount"] = rulesCount

	// Extract open ports
	openPorts := []int{}
	portRegex := regexp.MustCompile(`(\d+)(?:/tcp|/udp)?\s+ALLOW`)
	matches := portRegex.FindAllStringSubmatch(result.Stdout, -1)
	for _, match := range matches {
		if len(match) > 1 {
			if port, err := strconv.Atoi(match[1]); err == nil {
				openPorts = append(openPorts, port)
			}
		}
	}
	data["openPorts"] = openPorts

	return "ufw", data
}

func (a *FirewallAnalyzer) analyzeFirewalld(ctx context.Context) (string, map[string]interface{}) {
	if !system.CommandExists("firewall-cmd") {
		return "", nil
	}

	result, err := system.RunCommandSudo(ctx, system.TimeoutShort, "firewall-cmd", "--state")
	if err != nil || result == nil {
		return "", nil
	}

	data := make(map[string]interface{})
	data["type"] = "firewalld"
	data["active"] = result.Success && strings.TrimSpace(result.Stdout) == "running"

	// Get services
	if servicesResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "firewall-cmd", "--list-services"); servicesResult != nil && servicesResult.Success {
		services := strings.Fields(servicesResult.Stdout)
		data["services"] = services
		data["rulesCount"] = len(services)
	}

	return "firewalld", data
}

func (a *FirewallAnalyzer) analyzeIptables(ctx context.Context) (string, map[string]interface{}) {
	if !system.CommandExists("iptables") {
		return "", nil
	}

	result, err := system.RunCommandSudo(ctx, system.TimeoutShort, "iptables", "-L", "-n")
	if err != nil || result == nil || !result.Success {
		return "", nil
	}

	data := make(map[string]interface{})
	data["type"] = "iptables"

	// Count non-header lines as rules
	rulesCount := 0
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "Chain") && !strings.HasPrefix(line, "target") {
			rulesCount++
		}
	}

	data["active"] = rulesCount > 0
	data["rulesCount"] = rulesCount

	return "iptables", data
}

func (a *FirewallAnalyzer) addFirewallIssues(result *Result, data map[string]interface{}) {
	active, _ := data["active"].(bool)
	fwType, _ := data["type"].(string)

	if !active {
		result.AddIssue(NewIssue(SeverityCritical, "Firewall is not active", "Enable the firewall immediately"))
		return
	}

	// Check default policy for UFW
	if fwType == "ufw" {
		if policy, ok := data["defaultPolicy"].(string); ok && policy == "allow" {
			result.AddIssue(NewIssue(SeverityHigh, "Firewall default policy is ALLOW", "Change default policy to DENY for better security"))
		}
	}

	// Check if too many ports are open
	if ports, ok := data["openPorts"].([]int); ok && len(ports) > 10 {
		result.AddIssue(NewIssue(SeverityMedium, "Many ports are open: "+strconv.Itoa(len(ports)), "Review open ports and close unnecessary ones"))
	}
}
