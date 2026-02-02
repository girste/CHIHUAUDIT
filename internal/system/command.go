package system

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/errors"
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
// RunCommand executes a command with timeout and returns structured result.
// When running in container with host PID namespace, commands execute on host.
func RunCommand(ctx context.Context, timeout time.Duration, cmdParts ...string) (*CommandResult, error) {
	if len(cmdParts) == 0 {
		return nil, errors.Wrap(errors.ErrInvalidInput, "no command specified")
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

	if result.TimedOut {
		return result, errors.Wrap(errors.ErrTimeoutExceeded, "command '%s' timed out after %v", cmdParts[0], timeout)
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
// Uses background context with short timeout for utility function
func CommandExists(cmd string) bool {
	return CommandExistsWithContext(context.Background(), cmd)
}

// CommandExistsWithContext checks if a command is available with custom context
func CommandExistsWithContext(ctx context.Context, cmd string) bool {
	if !IsInContainer() {
		// Native execution - use LookPath
		_, err := exec.LookPath(cmd)
		return err == nil
	}

	// In container - check on host using which
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutShort)
	defer cancel()

	result, err := RunCommand(timeoutCtx, TimeoutShort, "which", cmd)
	return err == nil && result != nil && result.Success
}

// IsServiceActive checks if a systemd service is active
func IsServiceActive(ctx context.Context, service string) bool {
	result, err := RunCommand(ctx, TimeoutShort, "systemctl", "is-active", service)
	if err != nil || result == nil {
		return false
	}
	return result.Success && strings.TrimSpace(result.Stdout) == "active"
}
