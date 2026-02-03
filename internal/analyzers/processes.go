package analyzers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
)

type ProcessAnalyzer struct{}

func (a *ProcessAnalyzer) Name() string           { return "processes" }
func (a *ProcessAnalyzer) RequiresSudo() bool     { return true }
func (a *ProcessAnalyzer) Timeout() time.Duration { return system.TimeoutShort }

// suspiciousExecPaths — legitimate software does not execute from these directories.
// A process running from /tmp or /dev/shm is a strong indicator of malicious activity.
var suspiciousExecPaths = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"}

// knownMaliciousNames — process names associated with known malware and miners.
var knownMaliciousNames = []string{
	"xmrig", "minergate", "cryptonight", "monero-miner",
	"strstrstr", "backdoor", "rootkit",
}

func (a *ProcessAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	// ps -ew: all processes. -o pid=,user=,args=: no header, wide args column.
	psResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "ps", "-ew", "-o", "pid=,user=,args=")
	if psResult == nil || !psResult.Success {
		result.Checked = false
		return result, nil
	}

	rootProcesses := []map[string]string{}
	suspicious := []map[string]string{}

	for _, line := range strings.Split(psResult.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		pid := fields[0]
		user := fields[1]
		args := strings.Join(fields[2:], " ")

		// Kernel threads are shown in brackets — skip, they're always legitimate
		if strings.HasPrefix(args, "[") {
			continue
		}

		if user == "root" {
			rootProcesses = append(rootProcesses, map[string]string{
				"pid":  pid,
				"args": args,
			})
		}

		argsLower := strings.ToLower(args)
		flagged := false

		// Flag processes executing from suspicious directories
		for _, path := range suspiciousExecPaths {
			if strings.Contains(argsLower, path) {
				suspicious = append(suspicious, map[string]string{"pid": pid, "user": user, "args": args})
				result.AddIssue(NewIssue(SeverityHigh,
					fmt.Sprintf("Process from suspicious path: %s (PID %s, user %s)", args, pid, user),
					"Investigate and terminate if unauthorized"))
				flagged = true
				break
			}
		}

		if flagged {
			continue
		}

		// Flag known malicious process names
		for _, name := range knownMaliciousNames {
			if strings.Contains(argsLower, name) {
				suspicious = append(suspicious, map[string]string{"pid": pid, "user": user, "args": args})
				result.AddIssue(NewIssue(SeverityCritical,
					fmt.Sprintf("Known malicious process: %s (PID %s, user %s)", args, pid, user),
					"Terminate immediately and investigate system compromise"))
				break
			}
		}
	}

	result.Data = map[string]interface{}{
		"rootProcessCount":    len(rootProcesses),
		"rootProcesses":       rootProcesses,
		"suspiciousCount":     len(suspicious),
		"suspiciousProcesses": suspicious,
	}

	return result, nil
}
