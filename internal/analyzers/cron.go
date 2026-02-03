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

type CronAnalyzer struct{}

func (a *CronAnalyzer) Name() string           { return "cron" }
func (a *CronAnalyzer) RequiresSudo() bool     { return true }
func (a *CronAnalyzer) Timeout() time.Duration { return system.TimeoutShort }

func (a *CronAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	cronJobs := []map[string]string{}
	systemdTimers := []string{}

	// /etc/crontab — system crontab (has user field)
	cronJobs = append(cronJobs, parseCronFile(ctx, system.HostPath("/etc/crontab"), "system", true)...)

	// /etc/cron.d/* — system drop-ins (have user field)
	cronDPath := system.HostPath("/etc/cron.d")
	if entries, err := os.ReadDir(cronDPath); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			cronJobs = append(cronJobs, parseCronFile(ctx, cronDPath+"/"+entry.Name(), "cron.d/"+entry.Name(), true)...)
		}
	}

	// User crontabs — try both RHEL and Debian locations
	for _, dir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		dirPath := system.HostPath(dir)
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			cronJobs = append(cronJobs, parseCronFile(ctx, dirPath+"/"+entry.Name(), "user:"+entry.Name(), false)...)
		}
		break // First readable directory wins
	}

	// Systemd timers
	hostExec := system.GetHostExecutor()
	timerResult, err := hostExec.RunHostCommand(ctx, system.TimeoutShort, "systemctl", "list-timers", "--all", "--no-pager")
	if err == nil && timerResult != nil && timerResult.Success {
		for _, line := range strings.Split(timerResult.Stdout, "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 3 && strings.HasSuffix(fields[2], ".timer") {
				systemdTimers = append(systemdTimers, fields[2])
			}
		}
	}

	result.Data = map[string]interface{}{
		"cronJobs":      cronJobs,
		"cronJobCount":  len(cronJobs),
		"systemdTimers": systemdTimers,
		"timerCount":    len(systemdTimers),
	}

	// Flag suspicious cron commands
	for _, job := range cronJobs {
		if isSuspiciousCronCommand(job["command"]) {
			result.AddIssue(NewIssue(SeverityHigh,
				"Suspicious cron job in "+job["source"]+": "+job["command"],
				"Review and remove if not authorized"))
		}
	}

	return result, nil
}

func parseCronFile(ctx context.Context, path, source string, hasUserField bool) []map[string]string {
	jobs := []map[string]string{}

	data, err := os.ReadFile(path)
	if err != nil {
		cmdResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "cat", path)
		if cmdResult == nil || !cmdResult.Success {
			return jobs
		}
		data = []byte(cmdResult.Stdout)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip variable assignments (KEY=value — no space before =, no time-spec chars)
		if eqIdx := strings.Index(line, "="); eqIdx > 0 {
			before := line[:eqIdx]
			if !strings.ContainsAny(before, "* /") {
				continue
			}
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		var schedule, command string

		if strings.HasPrefix(fields[0], "@") {
			// @shortcut format (@daily, @hourly, @reboot, etc.)
			schedule = fields[0]
			cmdStart := 1
			if hasUserField && len(fields) > 2 {
				cmdStart = 2
			}
			if cmdStart >= len(fields) {
				continue
			}
			command = strings.Join(fields[cmdStart:], " ")
		} else {
			// Standard 5-field time spec
			if len(fields) < 6 {
				continue
			}
			schedule = strings.Join(fields[:5], " ")
			cmdStart := 5
			if hasUserField {
				cmdStart = 6
				if len(fields) < 7 {
					continue
				}
			}
			command = strings.Join(fields[cmdStart:], " ")
		}

		jobs = append(jobs, map[string]string{
			"schedule": schedule,
			"command":  command,
			"source":   source,
		})
	}

	return jobs
}

// isSuspiciousCronCommand flags commands that match known malicious patterns.
// Legitimate tools like curl/wget are NOT flagged on their own — only when
// combined with shell execution, obfuscation, or known malware patterns.
func isSuspiciousCronCommand(cmd string) bool {
	lower := strings.ToLower(cmd)

	// Pipe to shell (classic injection: curl ... | bash)
	if strings.Contains(lower, "| bash") || strings.Contains(lower, "| sh ") ||
		strings.Contains(lower, "|bash") || strings.Contains(lower, "|sh ") {
		return true
	}

	// Base64 decode (common obfuscation layer)
	if strings.Contains(lower, "base64") && (strings.Contains(lower, "-d") || strings.Contains(lower, "--decode")) {
		return true
	}

	// Reverse shell patterns
	if strings.Contains(lower, "/dev/tcp") || strings.Contains(lower, "bash -i") || strings.Contains(lower, "sh -i >") {
		return true
	}

	// Known crypto miners
	for _, miner := range []string{"xmrig", "minergate", "cryptonight"} {
		if strings.Contains(lower, miner) {
			return true
		}
	}

	// eval with command substitution (eval $(cmd) or eval `cmd`)
	if strings.Contains(lower, "eval") && (strings.Contains(lower, "$(") || strings.Contains(lower, "`")) {
		return true
	}

	return false
}
