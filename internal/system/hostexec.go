package system

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/girste/chihuaudit/internal/errors"
	"github.com/girste/chihuaudit/internal/log"
)

// HostExecStrategy defines how to execute commands on the host system
type HostExecStrategy int

const (
	// StrategyAuto automatically selects the best strategy
	StrategyAuto HostExecStrategy = iota
	// StrategyDirectMount uses mounted host binaries from /host/usr/bin
	StrategyDirectMount
	// StrategyNsenter uses nsenter to enter host namespaces
	StrategyNsenter
	// StrategyFileRead fallback - only file reading, no command execution
	StrategyFileRead
)

// String returns the string representation of the strategy
func (s HostExecStrategy) String() string {
	switch s {
	case StrategyAuto:
		return "auto"
	case StrategyDirectMount:
		return "direct_mount"
	case StrategyNsenter:
		return "nsenter"
	case StrategyFileRead:
		return "file_read"
	default:
		return "unknown"
	}
}

// ExecutionMetrics tracks execution statistics for observability
type ExecutionMetrics struct {
	TotalCalls    int64
	SuccessCalls  int64
	FailedCalls   int64
	TimeoutCalls  int64
	StrategyUsage map[HostExecStrategy]int64
}

// HostCommandExecutor manages host command execution with security controls
type HostCommandExecutor struct {
	strategy        HostExecStrategy
	hostBinPaths    []string // Multiple paths to check: /host/usr/bin, /host/usr/sbin
	allowedBinaries map[string]bool
	metrics         *ExecutionMetrics
	metricsMu       sync.RWMutex // Protects metrics access
	mu              sync.RWMutex
}

var (
	// Global singleton instance
	globalExecutor *HostCommandExecutor
	executorOnce   sync.Once
)

// GetHostExecutor returns the global HostCommandExecutor singleton
func GetHostExecutor() *HostCommandExecutor {
	executorOnce.Do(func() {
		globalExecutor = NewHostCommandExecutor()
	})
	return globalExecutor
}

// NewHostCommandExecutor creates a new host command executor with security defaults
func NewHostCommandExecutor() *HostCommandExecutor {
	executor := &HostCommandExecutor{
		strategy: StrategyAuto,
		hostBinPaths: []string{
			"/host/usr/bin",
			"/host/usr/sbin",
			"/host/bin",
			"/host/sbin",
		},
		allowedBinaries: make(map[string]bool),
		metrics: &ExecutionMetrics{
			StrategyUsage: make(map[HostExecStrategy]int64),
		},
	}

	// Initialize whitelist of allowed binaries
	executor.initializeWhitelist()

	// Auto-detect best strategy
	executor.detectStrategy()

	return executor
}

// initializeWhitelist sets up the allowed binaries whitelist
func (h *HostCommandExecutor) initializeWhitelist() {
	// System administration
	h.allowedBinaries["systemctl"] = true
	h.allowedBinaries["service"] = true
	h.allowedBinaries["journalctl"] = true

	// User management
	h.allowedBinaries["getent"] = true
	h.allowedBinaries["id"] = true
	h.allowedBinaries["who"] = true
	h.allowedBinaries["w"] = true

	// Security tools
	h.allowedBinaries["fail2ban-client"] = true
	h.allowedBinaries["iptables"] = true
	h.allowedBinaries["ip6tables"] = true
	h.allowedBinaries["firewall-cmd"] = true
	h.allowedBinaries["ufw"] = true

	// Network tools
	h.allowedBinaries["ss"] = true
	h.allowedBinaries["netstat"] = true
	h.allowedBinaries["ip"] = true

	// Package managers
	h.allowedBinaries["apt"] = true
	h.allowedBinaries["apt-get"] = true
	h.allowedBinaries["yum"] = true
	h.allowedBinaries["dnf"] = true
	h.allowedBinaries["zypper"] = true
	h.allowedBinaries["pacman"] = true

	// Docker
	h.allowedBinaries["docker"] = true

	// File operations (read-only)
	h.allowedBinaries["cat"] = true
	h.allowedBinaries["head"] = true
	h.allowedBinaries["tail"] = true
	h.allowedBinaries["ls"] = true
	h.allowedBinaries["find"] = true
	h.allowedBinaries["stat"] = true

	// Text processing
	h.allowedBinaries["grep"] = true
	h.allowedBinaries["awk"] = true
	h.allowedBinaries["sed"] = true
	h.allowedBinaries["cut"] = true

	// System info
	h.allowedBinaries["uname"] = true
	h.allowedBinaries["hostname"] = true
	h.allowedBinaries["uptime"] = true
	h.allowedBinaries["ps"] = true
	h.allowedBinaries["lsof"] = true
	h.allowedBinaries["which"] = true
}

// detectStrategy determines the best execution strategy for the current environment
func (h *HostCommandExecutor) detectStrategy() {
	h.mu.Lock()
	defer h.mu.Unlock()

	// If not in container, use direct execution (no /host prefix needed)
	if !IsInContainer() {
		h.strategy = StrategyDirectMount
		log.Debug("HostExecutor: Native execution (not in container)")
		return
	}

	// Check if host binaries are mounted and accessible
	for _, binPath := range h.hostBinPaths {
		testBinary := filepath.Join(binPath, "systemctl")
		if FileExists(testBinary) {
			h.strategy = StrategyDirectMount
			log.Debugf("HostExecutor: Using DirectMount strategy (host binaries available at %s)", binPath)
			return
		}
	}

	// Check if nsenter is available in container
	if _, err := exec.LookPath("nsenter"); err == nil {
		h.strategy = StrategyNsenter
		log.Debug("HostExecutor: Using Nsenter strategy")
		return
	}

	// Fallback: file reading only
	h.strategy = StrategyFileRead
	log.Warn("HostExecutor: No command execution available, using FileRead fallback")
}

// RunHostCommand executes a command on the host with the appropriate strategy
func (h *HostCommandExecutor) RunHostCommand(
	ctx context.Context,
	timeout time.Duration,
	cmdParts ...string,
) (*CommandResult, error) {
	h.metricsMu.Lock()
	h.metrics.TotalCalls++
	h.metricsMu.Unlock()

	if len(cmdParts) == 0 {
		return nil, errors.Wrap(errors.ErrInvalidInput, "no command specified")
	}

	cmdName := cmdParts[0]

	// Security: Whitelist check
	if !h.isCommandAllowed(cmdName) {
		h.metricsMu.Lock()
		h.metrics.FailedCalls++
		h.metricsMu.Unlock()
		return nil, errors.Wrap(errors.ErrInvalidInput, "command '%s' not in whitelist", cmdName)
	}

	// Get current strategy
	h.mu.RLock()
	strategy := h.strategy
	h.mu.RUnlock()

	// Execute based on strategy
	var result *CommandResult
	var err error

	startTime := time.Now()

	switch strategy {
	case StrategyDirectMount:
		result, err = h.execViaMountedBinary(ctx, timeout, cmdParts...)
	case StrategyNsenter:
		result, err = h.execViaNsenter(ctx, timeout, cmdParts...)
	case StrategyFileRead:
		return nil, errors.Wrap(errors.ErrInvalidInput, "command execution not available in FileRead mode")
	default:
		return nil, errors.Wrap(errors.ErrInvalidInput, "unknown execution strategy")
	}

	duration := time.Since(startTime)

	// Update metrics
	h.metricsMu.Lock()
	h.metrics.StrategyUsage[strategy]++
	if err != nil || (result != nil && !result.Success) {
		h.metrics.FailedCalls++
	} else {
		h.metrics.SuccessCalls++
	}
	if result != nil && result.TimedOut {
		h.metrics.TimeoutCalls++
	}
	h.metricsMu.Unlock()

	// Audit logging
	h.logExecution(cmdParts, strategy, result, err, duration)

	return result, err
}

// execViaMountedBinary executes command using mounted host binaries
func (h *HostCommandExecutor) execViaMountedBinary(
	ctx context.Context,
	timeout time.Duration,
	cmdParts ...string,
) (*CommandResult, error) {
	cmdName := cmdParts[0]
	var hostBinary string

	// Find the binary in mounted host paths
	for _, binPath := range h.hostBinPaths {
		candidatePath := filepath.Join(binPath, cmdName)
		if FileExists(candidatePath) {
			hostBinary = candidatePath
			break
		}
	}

	if hostBinary == "" {
		// Try without /host prefix (native execution or command not found)
		if !IsInContainer() {
			hostBinary = cmdName
		} else {
			return nil, fmt.Errorf("host binary not found: %s", cmdName)
		}
	}

	// Build full command with host binary path
	fullCmd := append([]string{hostBinary}, cmdParts[1:]...)

	// Execute using standard RunCommand
	return RunCommand(ctx, timeout, fullCmd...)
}

// execViaNsenter executes command via nsenter into host namespaces
func (h *HostCommandExecutor) execViaNsenter(
	ctx context.Context,
	timeout time.Duration,
	cmdParts ...string,
) (*CommandResult, error) {
	// nsenter -t 1 -m -u -n -i -- cmd args...
	// -t 1: target PID 1 (init/systemd on host)
	// -m: enter mount namespace (critical for filesystem access)
	// -u: enter UTS namespace (hostname)
	// -n: enter network namespace
	// -i: enter IPC namespace

	nsenterCmd := []string{
		"nsenter",
		"-t", "1", // Target PID 1
		"-m", // Mount namespace
		"-u", // UTS namespace
		"-n", // Network namespace
		"-i", // IPC namespace
		"--", // End of nsenter options
	}

	fullCmd := append(nsenterCmd, cmdParts...)

	// Execute using standard RunCommand
	return RunCommand(ctx, timeout, fullCmd...)
}

// isCommandAllowed checks if a command is in the whitelist
func (h *HostCommandExecutor) isCommandAllowed(cmdName string) bool {
	// Extract base command name (remove path)
	baseName := filepath.Base(cmdName)

	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.allowedBinaries[baseName]
}

// AddAllowedCommand adds a command to the whitelist (for extensibility)
func (h *HostCommandExecutor) AddAllowedCommand(cmdName string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.allowedBinaries[cmdName] = true
	log.Infof("HostExecutor: Added '%s' to whitelist", cmdName)
}

// RemoveAllowedCommand removes a command from the whitelist
func (h *HostCommandExecutor) RemoveAllowedCommand(cmdName string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.allowedBinaries, cmdName)
	log.Infof("HostExecutor: Removed '%s' from whitelist", cmdName)
}

// GetStrategy returns the current execution strategy
func (h *HostCommandExecutor) GetStrategy() HostExecStrategy {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.strategy
}

// SetStrategy manually sets the execution strategy (for testing)
func (h *HostCommandExecutor) SetStrategy(strategy HostExecStrategy) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.strategy = strategy
	log.Infof("HostExecutor: Strategy set to %s", strategy.String())
}

// GetMetrics returns a copy of execution metrics
func (h *HostCommandExecutor) GetMetrics() ExecutionMetrics {
	h.metricsMu.RLock()
	defer h.metricsMu.RUnlock()

	// Return a copy to prevent race conditions
	metricsCopy := ExecutionMetrics{
		TotalCalls:    h.metrics.TotalCalls,
		SuccessCalls:  h.metrics.SuccessCalls,
		FailedCalls:   h.metrics.FailedCalls,
		TimeoutCalls:  h.metrics.TimeoutCalls,
		StrategyUsage: make(map[HostExecStrategy]int64),
	}

	for k, v := range h.metrics.StrategyUsage {
		metricsCopy.StrategyUsage[k] = v
	}

	return metricsCopy
}

// ResetMetrics resets all metrics to zero (for testing)
func (h *HostCommandExecutor) ResetMetrics() {
	h.metricsMu.Lock()
	defer h.metricsMu.Unlock()

	h.metrics.TotalCalls = 0
	h.metrics.SuccessCalls = 0
	h.metrics.FailedCalls = 0
	h.metrics.TimeoutCalls = 0
	h.metrics.StrategyUsage = make(map[HostExecStrategy]int64)
}

// logExecution logs command execution for audit trail
func (h *HostCommandExecutor) logExecution(
	cmdParts []string,
	strategy HostExecStrategy,
	result *CommandResult,
	err error,
	duration time.Duration,
) {
	cmdStr := strings.Join(cmdParts, " ")

	if err != nil {
		log.Errorf("Host command failed: command=%s strategy=%s error=%v duration=%s",
			cmdStr, strategy.String(), err, duration.String())
		return
	}

	if result != nil {
		if result.TimedOut {
			log.Warnf("Host command timed out: command=%s strategy=%s duration=%s",
				cmdStr, strategy.String(), duration.String())
		} else if !result.Success {
			log.Warnf("Host command returned non-zero exit code: command=%s strategy=%s exitCode=%d stderr=%s duration=%s",
				cmdStr, strategy.String(), result.ExitCode, truncateString(result.Stderr, 200), duration.String())
		} else {
			log.Debugf("Host command executed successfully: command=%s strategy=%s duration=%s",
				cmdStr, strategy.String(), duration.String())
		}
	}
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
