package system

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CommandResult represents the result of a command execution
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Success  bool
	TimedOut bool
}

const (
	TimeoutShort    = 5 * time.Second
	TimeoutMedium   = 10 * time.Second
	TimeoutLong     = 30 * time.Second
	TimeoutVeryLong = 120 * time.Second
)

// RunCommand executes a command with timeout
func RunCommand(ctx context.Context, timeout time.Duration, cmdParts ...string) (*CommandResult, error) {
	if len(cmdParts) == 0 {
		return nil, fmt.Errorf("no command specified")
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdParts[0], cmdParts[1:]...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Success:  err == nil,
		TimedOut: ctx.Err() == context.DeadlineExceeded,
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
	} else if err == nil {
		result.ExitCode = 0
	}

	return result, nil
}

// RunCommandSudo tries without sudo first, falls back to sudo if permission denied
func RunCommandSudo(ctx context.Context, timeout time.Duration, cmdParts ...string) (*CommandResult, error) {
	// Try without sudo first
	result, err := RunCommand(ctx, timeout, cmdParts...)
	if err != nil {
		return result, err
	}

	// Check if permission denied
	stderrLower := strings.ToLower(result.Stderr)
	needsSudo := strings.Contains(stderrLower, "permission denied") ||
		strings.Contains(stderrLower, "you must be root") ||
		strings.Contains(stderrLower, "you need to be root") ||
		strings.Contains(stderrLower, "operation not permitted")

	// Special case: commands in /sbin or /usr/sbin often need sudo
	if len(cmdParts) > 0 {
		cmdPath := cmdParts[0]
		if strings.HasPrefix(cmdPath, "/sbin/") || strings.HasPrefix(cmdPath, "/usr/sbin/") {
			needsSudo = true
		}
	}

	if !needsSudo && result.Success {
		return result, nil
	}

	// Retry with sudo -n (no password prompt)
	sudoCmd := append([]string{"sudo", "-n"}, cmdParts...)
	return RunCommand(ctx, timeout, sudoCmd...)
}

// CommandExists checks if a command is available
func CommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// IsServiceActive checks if a systemd service is active
func IsServiceActive(ctx context.Context, service string) bool {
	result, err := RunCommand(ctx, TimeoutShort, "systemctl", "is-active", service)
	if err != nil || result == nil {
		return false
	}
	return result.Success && strings.TrimSpace(result.Stdout) == "active"
}
