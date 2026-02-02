package analyzers

import (
	"bufio"
	"context"
	"os"
	"strconv"
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

	// Read passwd file directly from host
	passwdPath := system.HostPath("/etc/passwd")
	passwdFile, err := os.Open(passwdPath)
	if err != nil {
		result.Checked = false
		return result, nil
	}
	defer passwdFile.Close()

	uidZeroUsers := []string{}
	usersWithoutPassword := []string{}
	interactiveUsers := []string{}
	usersWithWeakHash := []string{}

	// Parse passwd file
	scanner := bufio.NewScanner(passwdFile)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		username := parts[0]
		uidStr := parts[2]
		shell := parts[6]

		// Parse UID
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			continue
		}

		// Check for UID 0 (root equivalent)
		if uid == 0 && username != "root" {
			uidZeroUsers = append(uidZeroUsers, username)
		}

		// Check for interactive shell
		if isInteractiveShell(shell) {
			interactiveUsers = append(interactiveUsers, username)
		}
	}

	// Read shadow file directly from host (requires elevated privileges)
	shadowPath := system.HostPath("/etc/shadow")
	shadowFile, err := os.Open(shadowPath)
	if err == nil {
		defer shadowFile.Close()

		shadowScanner := bufio.NewScanner(shadowFile)
		for shadowScanner.Scan() {
			line := shadowScanner.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parts := strings.Split(line, ":")
			if len(parts) < 2 {
				continue
			}

			username := parts[0]
			passwordHash := parts[1]

			// Check for locked/disabled accounts
			if isAccountLocked(passwordHash) {
				// Check if it's an interactive user
				if isUserInList(username, interactiveUsers) {
					usersWithoutPassword = append(usersWithoutPassword, username)
				}
			} else if hasWeakPasswordHash(passwordHash) {
				// Check for weak hashes (MD5, DES)
				usersWithWeakHash = append(usersWithWeakHash, username)
			}
		}
	}

	result.Data = map[string]interface{}{
		"uidZeroUsers":         uidZeroUsers,
		"usersWithoutPassword": usersWithoutPassword,
		"usersWithWeakHash":    usersWithWeakHash,
		"interactiveUserCount": len(interactiveUsers),
	}

	// Add issues
	if len(uidZeroUsers) > 0 {
		result.AddIssue(NewIssue(SeverityCritical, "Non-root users with UID 0 found: "+strings.Join(uidZeroUsers, ", "), "Remove or fix UID 0 users"))
	}

	if len(usersWithoutPassword) > 0 {
		result.AddIssue(NewIssue(SeverityHigh, "Interactive users without password: "+strings.Join(usersWithoutPassword, ", "), "Set passwords or disable accounts"))
	}

	if len(usersWithWeakHash) > 0 {
		result.AddIssue(NewIssue(SeverityHigh, "Users with weak password hashes: "+strings.Join(usersWithWeakHash, ", "), "Upgrade to SHA-512 or better"))
	}

	return result, nil
}

// isInteractiveShell checks if a shell is interactive
func isInteractiveShell(shell string) bool {
	interactiveShells := []string{
		"/bin/bash",
		"/bin/sh",
		"/bin/zsh",
		"/bin/fish",
		"/bin/ksh",
		"/usr/bin/bash",
		"/usr/bin/sh",
		"/usr/bin/zsh",
		"/usr/bin/fish",
		"/usr/bin/ksh",
	}

	for _, s := range interactiveShells {
		if shell == s {
			return true
		}
	}

	return false
}

// isAccountLocked checks if an account is locked or has no password
func isAccountLocked(passwordHash string) bool {
	// Empty, !, !!, *, or *LK* indicates locked/disabled account
	return passwordHash == "" ||
		passwordHash == "!" ||
		passwordHash == "!!" ||
		passwordHash == "*" ||
		passwordHash == "*LK*" ||
		passwordHash == "!*"
}

// hasWeakPasswordHash detects weak password hashing algorithms
func hasWeakPasswordHash(passwordHash string) bool {
	if len(passwordHash) == 0 {
		return false
	}

	// DES: no prefix, 13 chars
	if !strings.HasPrefix(passwordHash, "$") && len(passwordHash) == 13 {
		return true
	}

	// MD5: $1$
	if strings.HasPrefix(passwordHash, "$1$") {
		return true
	}

	// Blowfish (old): $2$ or $2a$
	if strings.HasPrefix(passwordHash, "$2$") || strings.HasPrefix(passwordHash, "$2a$") {
		return true
	}

	// SHA-256 ($5$) and SHA-512 ($6$) are acceptable
	// yescrypt ($y$) and Argon2 ($argon2$) are good
	return false
}

// isUserInList checks if a user exists in a list
func isUserInList(username string, userList []string) bool {
	for _, u := range userList {
		if u == username {
			return true
		}
	}
	return false
}
