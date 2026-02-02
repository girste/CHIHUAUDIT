package analyzers

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
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
	result.AddIssue(NewIssue(SeverityCritical, "No firewall", "Install ufw"))

	return result, nil
}

func (a *FirewallAnalyzer) analyzeUFW(ctx context.Context) (string, map[string]interface{}) {
	ufwConfPath := system.HostPath("/etc/ufw/ufw.conf")

	// Check if UFW config exists
	if !system.FileExists(ufwConfPath) {
		return "", nil
	}

	data := make(map[string]interface{})
	data["type"] = "ufw"

	// Read UFW config to check if enabled
	configData, err := os.ReadFile(ufwConfPath)
	active := false
	if err == nil {
		configStr := string(configData)
		active = strings.Contains(configStr, "ENABLED=yes")
	}
	data["active"] = active

	// Try to read user rules to count them and extract ports
	userRulesPath := system.HostPath("/etc/ufw/user.rules")
	rulesCount := 0
	openPorts := []int{}

	if rulesData, err := os.ReadFile(userRulesPath); err == nil {
		lines := strings.Split(string(rulesData), "\n")
		for _, line := range lines {
			// Skip comments and empty lines
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Count iptables rules
			if strings.HasPrefix(line, "-A") {
				rulesCount++
				// Try to extract port numbers
				portRegex := regexp.MustCompile(`--dport (\d+)`)
				if matches := portRegex.FindStringSubmatch(line); len(matches) > 1 {
					if port, err := strconv.Atoi(matches[1]); err == nil {
						openPorts = append(openPorts, port)
					}
				}
			}
		}
	}

	data["rulesCount"] = rulesCount
	data["openPorts"] = openPorts
	data["defaultPolicy"] = "deny" // UFW defaults to deny

	return "ufw", data
}

func (a *FirewallAnalyzer) analyzeFirewalld(ctx context.Context) (string, map[string]interface{}) {
	// Check if firewalld is running by looking for the process
	if !system.IsProcessRunning("firewalld") {
		return "", nil
	}

	data := make(map[string]interface{})
	data["type"] = "firewalld"
	data["active"] = true

	// Try to get services if firewall-cmd is available
	if system.CommandExists("firewall-cmd") {
		if servicesResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "firewall-cmd", "--list-services"); servicesResult != nil && servicesResult.Success {
			services := strings.Fields(servicesResult.Stdout)
			data["services"] = services
			data["rulesCount"] = len(services)
		}
	}

	return "firewalld", data
}

func (a *FirewallAnalyzer) analyzeIptables(ctx context.Context) (string, map[string]interface{}) {
	// Check if iptables is loaded by reading /proc/net/ip_tables_names
	tablesPath := system.HostPath("/proc/net/ip_tables_names")
	tablesData, err := os.ReadFile(tablesPath)
	if err != nil || len(tablesData) == 0 {
		// No iptables tables loaded
		return "", nil
	}

	data := make(map[string]interface{})
	data["type"] = "iptables"
	data["active"] = true

	// Try to count rules if iptables command is available
	if system.CommandExists("iptables") {
		result, err := system.RunCommandSudo(ctx, system.TimeoutShort, "iptables", "-L", "-n")
		if err == nil && result != nil && result.Success {
			// Count non-header lines as rules
			rulesCount := 0
			for _, line := range strings.Split(result.Stdout, "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "Chain") && !strings.HasPrefix(line, "target") {
					rulesCount++
				}
			}
			data["rulesCount"] = rulesCount
		}
	}

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
