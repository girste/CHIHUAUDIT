package analyzers

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/log"
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

	// Try to get jail information via HostExecutor
	jails := []string{}
	totalBanned := 0
	jailDetails := []map[string]interface{}{}

	hostExec := system.GetHostExecutor()
	statusResult, err := hostExec.RunHostCommand(ctx, system.TimeoutShort, "fail2ban-client", "status")

	if err == nil && statusResult != nil && statusResult.Success {
		// Extract jail list from fail2ban-client output
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

			jailStatusResult, err := hostExec.RunHostCommand(ctx, system.TimeoutShort, "fail2ban-client", "status", jail)
			if err != nil || jailStatusResult == nil || !jailStatusResult.Success {
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
	} else {
		// Fallback: Read jail configuration files directly
		log.Debug("fail2ban-client not available, falling back to config file reading")
		jails = readJailsFromConfig()

		for _, jail := range jails {
			jailDetails = append(jailDetails, map[string]interface{}{
				"name":   jail,
				"banned": 0, // Can't determine without client
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

// readJailsFromConfig reads jail names from fail2ban configuration files
func readJailsFromConfig() []string {
	jails := []string{}
	jailConfigDirs := []string{
		system.HostPath("/etc/fail2ban/jail.d"),
		system.HostPath("/etc/fail2ban/jail.local"),
	}

	enabledJailRegex := regexp.MustCompile(`\[([^\]]+)\]`)

	for _, configPath := range jailConfigDirs {
		// Check if it's a directory
		info, err := os.Stat(configPath)
		if err != nil {
			continue
		}

		if info.IsDir() {
			// Read all .conf and .local files in directory
			files, err := filepath.Glob(filepath.Join(configPath, "*.conf"))
			if err != nil {
				continue
			}

			localFiles, err := filepath.Glob(filepath.Join(configPath, "*.local"))
			if err == nil {
				files = append(files, localFiles...)
			}

			for _, file := range files {
				jailsFromFile := parseJailFile(file, enabledJailRegex)
				jails = append(jails, jailsFromFile...)
			}
		} else {
			// Single file
			jailsFromFile := parseJailFile(configPath, enabledJailRegex)
			jails = append(jails, jailsFromFile...)
		}
	}

	return jails
}

// parseJailFile extracts enabled jail names from a configuration file
func parseJailFile(filePath string, jailRegex *regexp.Regexp) []string {
	jails := []string{}

	file, err := os.Open(filePath)
	if err != nil {
		return jails
	}
	defer file.Close()

	currentJail := ""
	isEnabled := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for jail section header
		if matches := jailRegex.FindStringSubmatch(line); len(matches) > 1 {
			// Save previous jail if it was enabled
			if currentJail != "" && isEnabled {
				jails = append(jails, currentJail)
			}

			currentJail = matches[1]
			isEnabled = false // Reset for new section
			continue
		}

		// Check for enabled = true
		if strings.Contains(line, "enabled") && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				value := strings.TrimSpace(parts[1])
				if value == "true" || value == "True" || value == "TRUE" {
					isEnabled = true
				}
			}
		}
	}

	// Don't forget the last jail
	if currentJail != "" && isEnabled {
		jails = append(jails, currentJail)
	}

	return jails
}
