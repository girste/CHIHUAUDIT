package analyzers

import (
	"context"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
)

type UsersAnalyzer struct{}

func (a *UsersAnalyzer) Name() string           { return "users" }
func (a *UsersAnalyzer) RequiresSudo() bool     { return true }
func (a *UsersAnalyzer) Timeout() time.Duration { return system.TimeoutShort }

func (a *UsersAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	// Get all users
	passwdResult, _ := system.RunCommand(ctx, system.TimeoutShort, "getent", "passwd")
	if passwdResult == nil || !passwdResult.Success {
		result.Checked = false
		return result, nil
	}

	// Get shadow file (password hashes)
	shadowResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "getent", "shadow")

	uidZeroUsers := []string{}
	usersWithoutPassword := []string{}
	interactiveUsers := []string{}

	// Parse passwd
	for _, line := range strings.Split(passwdResult.Stdout, "\n") {
		if line == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		username := parts[0]
		uid := parts[2]
		shell := parts[6]

		// Check for UID 0 (root equivalent)
		if uid == "0" && username != "root" {
			uidZeroUsers = append(uidZeroUsers, username)
		}

		// Check for interactive shell
		if strings.HasSuffix(shell, "/bash") || strings.HasSuffix(shell, "/sh") || strings.HasSuffix(shell, "/zsh") {
			interactiveUsers = append(interactiveUsers, username)
		}
	}

	// Parse shadow if available
	if shadowResult != nil && shadowResult.Success {
		for _, line := range strings.Split(shadowResult.Stdout, "\n") {
			if line == "" {
				continue
			}

			parts := strings.Split(line, ":")
			if len(parts) < 2 {
				continue
			}

			username := parts[0]
			passwordHash := parts[1]

			// Check for empty or disabled password
			if passwordHash == "" || passwordHash == "!" || passwordHash == "*" || passwordHash == "!!" {
				// Check if it's an interactive user
				for _, interactive := range interactiveUsers {
					if interactive == username {
						usersWithoutPassword = append(usersWithoutPassword, username)
						break
					}
				}
			}
		}
	}

	result.Data = map[string]interface{}{
		"uidZeroUsers":         uidZeroUsers,
		"usersWithoutPassword": usersWithoutPassword,
		"interactiveUserCount": len(interactiveUsers),
	}

	// Add issues
	if len(uidZeroUsers) > 0 {
		result.AddIssue(NewIssue(SeverityCritical, "Non-root users with UID 0 found: "+strings.Join(uidZeroUsers, ", "), "Remove or fix UID 0 users"))
	}

	if len(usersWithoutPassword) > 0 {
		result.AddIssue(NewIssue(SeverityHigh, "Interactive users without password: "+strings.Join(usersWithoutPassword, ", "), "Set passwords or disable accounts"))
	}

	return result, nil
}
