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

type Fail2banAnalyzer struct{}

func (a *Fail2banAnalyzer) Name() string           { return "fail2ban" }
func (a *Fail2banAnalyzer) RequiresSudo() bool     { return true }
func (a *Fail2banAnalyzer) Timeout() time.Duration { return system.TimeoutShort }

func (a *Fail2banAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	if !system.CommandExists("fail2ban-client") {
		installed := false
		result.SetInstalled(installed)
		result.AddIssue(NewIssue(SeverityMedium, "Fail2ban is not installed", "Install fail2ban to protect against brute force attacks"))
		return result, nil
	}

	installed := true
	result.SetInstalled(installed)

	// Check if fail2ban is active
	statusResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "fail2ban-client", "status")
	if statusResult == nil || !statusResult.Success {
		active := false
		result.SetActive(active)
		result.AddIssue(NewIssue(SeverityHigh, "Fail2ban is installed but not running", "Start fail2ban service"))
		return result, nil
	}

	active := true
	result.SetActive(active)

	// Extract jail list
	jailRegex := regexp.MustCompile(`Jail list:\s+(.+)`)
	jailMatch := jailRegex.FindStringSubmatch(statusResult.Stdout)

	jails := []string{}
	if len(jailMatch) > 1 {
		jails = strings.Split(strings.TrimSpace(jailMatch[1]), ",")
		for i := range jails {
			jails[i] = strings.TrimSpace(jails[i])
		}
	}

	// Get banned count per jail
	totalBanned := 0
	jailDetails := []map[string]interface{}{}

	for _, jail := range jails {
		if jail == "" {
			continue
		}

		jailStatusResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "fail2ban-client", "status", jail)
		if jailStatusResult == nil || !jailStatusResult.Success {
			continue
		}

		bannedRegex := regexp.MustCompile(`Currently banned:\s+(\d+)`)
		bannedMatch := bannedRegex.FindStringSubmatch(jailStatusResult.Stdout)

		banned := 0
		if len(bannedMatch) > 1 {
			banned, _ = strconv.Atoi(bannedMatch[1])
		}

		totalBanned += banned

		jailDetails = append(jailDetails, map[string]interface{}{
			"name":   jail,
			"banned": banned,
		})
	}

	result.Data = map[string]interface{}{
		"jails":       jails,
		"totalBanned": totalBanned,
		"jailDetails": jailDetails,
	}

	return result, nil
}
