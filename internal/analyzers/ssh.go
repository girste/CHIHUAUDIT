package analyzers

import (
	"context"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/girste/mcp-cybersec-watchdog/internal/config"
	"github.com/girste/mcp-cybersec-watchdog/internal/system"
)

type SSHAnalyzer struct{}

func (a *SSHAnalyzer) Name() string           { return "ssh" }
func (a *SSHAnalyzer) RequiresSudo() bool     { return false }
func (a *SSHAnalyzer) Timeout() time.Duration { return system.TimeoutShort }

func (a *SSHAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	configPath := "/etc/ssh/sshd_config"
	data, err := os.ReadFile(configPath)
	if err != nil {
		// Try with sudo
		cmdResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "cat", configPath)
		if cmdResult == nil || !cmdResult.Success {
			result.Checked = false
			result.AddIssue(NewIssue(SeverityInfo, "Cannot read SSH config", ""))
			return result, nil
		}
		data = []byte(cmdResult.Stdout)
	}

	configContent := string(data)

	// Parse SSH configuration
	port := a.extractValue(configContent, "Port", "22")
	permitRootLogin := a.extractValue(configContent, "PermitRootLogin", "prohibit-password")
	passwordAuth := a.extractValue(configContent, "PasswordAuthentication", "yes")
	pubkeyAuth := a.extractValue(configContent, "PubkeyAuthentication", "yes")

	result.Data = map[string]interface{}{
		"port":            port,
		"permitRootLogin": permitRootLogin,
		"passwordAuth":    passwordAuth,
		"pubkeyAuth":      pubkeyAuth,
	}

	// Check for security issues
	if permitRootLogin == "yes" {
		result.AddIssue(NewIssue(SeverityHigh, "Root login is enabled via SSH", "Set PermitRootLogin to 'no' in /etc/ssh/sshd_config"))
	}

	if passwordAuth == "yes" {
		result.AddIssue(NewIssue(SeverityMedium, "Password authentication is enabled", "Consider using public key authentication only"))
	}

	if port == "22" {
		result.AddIssue(NewIssue(SeverityLow, "SSH is running on default port 22", "Consider changing to a non-standard port"))
	}

	return result, nil
}

func (a *SSHAnalyzer) extractValue(content, key, defaultValue string) string {
	// Match uncommented lines
	pattern := `(?m)^\s*` + key + `\s+(.+?)(?:\s|$)`
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(content)
	if len(match) > 1 {
		return strings.TrimSpace(match[1])
	}

	// Try to parse port as number
	if key == "Port" {
		portPattern := regexp.MustCompile(`(?m)^\s*Port\s+(\d+)`)
		if portMatch := portPattern.FindStringSubmatch(content); len(portMatch) > 1 {
			return portMatch[1]
		}
	}

	return defaultValue
}
