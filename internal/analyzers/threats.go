package analyzers

import (
	"context"
	"os"
	"regexp"
	"sort"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
	"github.com/girste/chihuaudit/internal/util"
)

type ThreatsAnalyzer struct{}

func (a *ThreatsAnalyzer) Name() string           { return "threats" }
func (a *ThreatsAnalyzer) RequiresSudo() bool     { return true }
func (a *ThreatsAnalyzer) Timeout() time.Duration { return system.TimeoutMedium }

func (a *ThreatsAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	logPath := system.GetAuthLogPath(ctx)

	// Read auth log
	data, err := os.ReadFile(logPath)
	if err != nil {
		// Try with sudo
		cmdResult, _ := system.RunCommandSudo(ctx, system.TimeoutMedium, "cat", logPath)
		if cmdResult == nil || !cmdResult.Success {
			result.Checked = false
			return result, nil
		}
		data = []byte(cmdResult.Stdout)
	}

	logContent := string(data)

	// Parse failed login attempts
	pattern := regexp.MustCompile(`Failed password for .* from ([\d.]+)`)
	matches := pattern.FindAllStringSubmatch(logContent, -1)

	ipCounts := make(map[string]int)
	totalAttempts := 0

	for _, match := range matches {
		if len(match) > 1 {
			ip := match[1]
			ipCounts[ip]++
			totalAttempts++
		}
	}

	// Build top attackers list
	type attacker struct {
		IP       string `json:"ip"`
		Attempts int    `json:"attempts"`
	}

	topAttackers := []attacker{}
	for ip, count := range ipCounts {
		maskedIP := ip
		if cfg.MaskData {
			maskedIP = util.MaskIP(ip)
		}
		topAttackers = append(topAttackers, attacker{IP: maskedIP, Attempts: count})
	}

	// Sort by attempts (descending order)
	sort.Slice(topAttackers, func(i, j int) bool {
		return topAttackers[i].Attempts > topAttackers[j].Attempts
	})

	// Keep top 10
	if len(topAttackers) > 10 {
		topAttackers = topAttackers[:10]
	}

	result.Data = map[string]interface{}{
		"periodDays":    cfg.ThreatAnalysisDays,
		"totalAttempts": totalAttempts,
		"uniqueIPs":     len(ipCounts),
		"topAttackers":  topAttackers,
	}

	// Detect patterns
	patterns := []string{}
	if totalAttempts > 100 {
		patterns = append(patterns, "ssh_brute_force")
	}
	if len(ipCounts) > 50 {
		patterns = append(patterns, "distributed_attack")
	}
	result.Data["patterns"] = patterns

	// Add issues
	if totalAttempts > 500 {
		result.AddIssue(NewIssue(SeverityHigh, "High number of failed SSH attempts detected", "Enable fail2ban and consider changing SSH port"))
	} else if totalAttempts > 100 {
		result.AddIssue(NewIssue(SeverityMedium, "Moderate failed SSH attempts detected", "Monitor authentication logs regularly"))
	}

	return result, nil
}
