package analyzers

import (
	"bufio"
	"context"
	"os"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
)

type SudoAnalyzer struct{}

func (a *SudoAnalyzer) Name() string           { return "sudo" }
func (a *SudoAnalyzer) RequiresSudo() bool     { return true }
func (a *SudoAnalyzer) Timeout() time.Duration { return system.TimeoutShort }

func (a *SudoAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	usersWithSudo := []string{}
	groupsWithSudo := []string{}
	passwordlessSudo := []string{}
	rulesCount := 0

	// Parse main sudoers file
	sudoersPath := system.HostPath("/etc/sudoers")
	parseSudoersFile(ctx, sudoersPath, &usersWithSudo, &groupsWithSudo, &passwordlessSudo, &rulesCount)

	// Parse /etc/sudoers.d/* drop-in files
	sudoersDPath := system.HostPath("/etc/sudoers.d")
	if entries, err := os.ReadDir(sudoersDPath); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || strings.HasSuffix(entry.Name(), "~") {
				continue
			}
			parseSudoersFile(ctx, sudoersDPath+"/"+entry.Name(), &usersWithSudo, &groupsWithSudo, &passwordlessSudo, &rulesCount)
		}
	}

	result.Data = map[string]interface{}{
		"usersWithSudo":    usersWithSudo,
		"groupsWithSudo":   groupsWithSudo,
		"passwordlessSudo": passwordlessSudo,
		"rulesCount":       rulesCount,
	}

	if len(passwordlessSudo) > 0 {
		result.AddIssue(NewIssue(SeverityHigh,
			"NOPASSWD sudo for: "+strings.Join(passwordlessSudo, ", "),
			"Remove NOPASSWD unless strictly necessary"))
	}

	return result, nil
}

func parseSudoersFile(ctx context.Context, path string, users, groups, nopasswd *[]string, rulesCount *int) {
	data, err := os.ReadFile(path)
	if err != nil {
		cmdResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "cat", path)
		if cmdResult == nil || !cmdResult.Success {
			return
		}
		data = []byte(cmdResult.Stdout)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments, empty lines, Defaults, and include directives
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") ||
			strings.HasPrefix(line, "@include") || strings.HasPrefix(line, "Cmnd_Alias") ||
			strings.HasPrefix(line, "Host_Alias") || strings.HasPrefix(line, "User_Alias") {
			continue
		}

		// Rules contain "=" (runas specification like ALL=(ALL))
		if !strings.Contains(line, "=") {
			continue
		}

		*rulesCount++

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		subject := fields[0]
		if strings.HasPrefix(subject, "%") {
			// Group entry
			groupName := strings.TrimPrefix(subject, "%")
			if !sudoContains(*groups, groupName) {
				*groups = append(*groups, groupName)
			}
		} else {
			// User entry
			if !sudoContains(*users, subject) {
				*users = append(*users, subject)
			}
		}

		if strings.Contains(line, "NOPASSWD") {
			if !sudoContains(*nopasswd, subject) {
				*nopasswd = append(*nopasswd, subject)
			}
		}
	}
}

func sudoContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
