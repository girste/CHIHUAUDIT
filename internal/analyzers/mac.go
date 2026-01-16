package analyzers

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/girste/mcp-cybersec-watchdog/internal/config"
	"github.com/girste/mcp-cybersec-watchdog/internal/system"
)

type MACAnalyzer struct{}

func (a *MACAnalyzer) Name() string           { return "mac" }
func (a *MACAnalyzer) RequiresSudo() bool     { return true }
func (a *MACAnalyzer) Timeout() time.Duration { return system.TimeoutShort }

func (a *MACAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	// Try AppArmor first (Debian/Ubuntu)
	if macType, macData := a.analyzeAppArmor(ctx); macType != "" {
		result.Data = macData
		return result, nil
	}

	// Try SELinux (RHEL/CentOS)
	if macType, macData := a.analyzeSELinux(ctx); macType != "" {
		result.Data = macData
		return result, nil
	}

	// No MAC system found
	result.Data = map[string]interface{}{
		"type":    "none",
		"enabled": false,
	}
	result.AddIssue(NewIssue(SeverityMedium, "No MAC (Mandatory Access Control) system detected", "Consider enabling AppArmor or SELinux"))

	return result, nil
}

func (a *MACAnalyzer) analyzeAppArmor(ctx context.Context) (string, map[string]interface{}) {
	// Check if AppArmor module is loaded
	lsmodResult, _ := system.RunCommand(ctx, system.TimeoutShort, "lsmod")
	if lsmodResult == nil || !strings.Contains(lsmodResult.Stdout, "apparmor") {
		return "", nil
	}

	// Check if enabled
	if data, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		if strings.TrimSpace(string(data)) != "Y" {
			return "", nil
		}
	}

	data := map[string]interface{}{
		"type":    "apparmor",
		"enabled": true,
	}

	// Get status
	statusResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "apparmor_status")
	if statusResult == nil || !statusResult.Success {
		// Try aa-status
		statusResult, _ = system.RunCommandSudo(ctx, system.TimeoutShort, "aa-status")
	}

	if statusResult != nil && statusResult.Success {
		enforceRegex := regexp.MustCompile(`(\d+) profiles are in enforce mode`)
		complainRegex := regexp.MustCompile(`(\d+) profiles are in complain mode`)

		if match := enforceRegex.FindStringSubmatch(statusResult.Stdout); len(match) > 1 {
			count, _ := strconv.Atoi(match[1])
			data["enforceCount"] = count
		}

		if match := complainRegex.FindStringSubmatch(statusResult.Stdout); len(match) > 1 {
			count, _ := strconv.Atoi(match[1])
			data["complainCount"] = count
		}
	}

	return "apparmor", data
}

func (a *MACAnalyzer) analyzeSELinux(ctx context.Context) (string, map[string]interface{}) {
	if !system.CommandExists("getenforce") {
		return "", nil
	}

	result, _ := system.RunCommand(ctx, system.TimeoutShort, "getenforce")
	if result == nil || !result.Success {
		return "", nil
	}

	status := strings.ToLower(strings.TrimSpace(result.Stdout))

	data := map[string]interface{}{
		"type":    "selinux",
		"status":  status,
		"enabled": status == "enforcing" || status == "permissive",
	}

	return "selinux", data
}
