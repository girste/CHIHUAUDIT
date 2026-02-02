package analyzers

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
)

type Fail2banAnalyzer struct{}

func (a *Fail2banAnalyzer) Name() string           { return "fail2ban" }
func (a *Fail2banAnalyzer) RequiresSudo() bool     { return true }
func (a *Fail2banAnalyzer) Timeout() time.Duration { return system.TimeoutShort }

func (a *Fail2banAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	// Check if fail2ban process is running (works in container too)
	isRunning := system.IsProcessRunning("fail2ban-server")
	
	if !isRunning {
		result.SetInstalled(false)
		result.AddIssue(NewIssue(SeverityMedium, "Fail2ban is not installed or not running", "Install and start fail2ban to protect against brute force attacks"))
		return result, nil
	}

	result.SetInstalled(true)
	result.SetActive(true)

	// Try to get jail information if fail2ban-client is available
	// If not available (in container), just report it's running without jail details
	jails := []string{}
	totalBanned := 0
	jailDetails := []map[string]interface{}{}
	
	// Try to check jail status - this might fail in container without fail2ban-client
	statusResult, err := system.RunCommandSudo(ctx, system.TimeoutShort, "fail2ban-client", "status")
	if err == nil && statusResult != nil && statusResult.Success {
		// Extract jail list
		jailRegex := regexp.MustCompile(`Jail list:\s+(.+)`)
		jailMatch := jailRegex.FindStringSubmatch(statusResult.Stdout)

		if len(jailMatch) > 1 {
			jails = strings.Split(strings.TrimSpace(jailMatch[1]), ",")
			for i := range jails {
				jails[i] = strings.TrimSpace(jails[i])
			}
		}

		// Get banned count per jail
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
	}

	result.Data = map[string]interface{}{
		"jails":       jails,
		"totalBanned": totalBanned,
		"jailDetails": jailDetails,
	}

	return result, nil
}
