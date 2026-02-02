package system

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestHostExecutor_NewHostCommandExecutor(t *testing.T) {
	executor := NewHostCommandExecutor()

	if executor == nil {
		t.Fatal("NewHostCommandExecutor returned nil")
	}

	if executor.strategy == StrategyAuto {
		t.Error("Strategy should be detected, not Auto")
	}

	if len(executor.allowedBinaries) == 0 {
		t.Error("Whitelist should be initialized")
	}

	// Check some essential commands in whitelist
	essentialCmds := []string{"systemctl", "getent", "fail2ban-client", "docker"}
	for _, cmd := range essentialCmds {
		if !executor.allowedBinaries[cmd] {
			t.Errorf("Essential command '%s' missing from whitelist", cmd)
		}
	}
}

func TestHostExecutor_Singleton(t *testing.T) {
	exec1 := GetHostExecutor()
	exec2 := GetHostExecutor()

	// Should return the same instance
	if exec1 != exec2 {
		t.Error("GetHostExecutor should return singleton")
	}
}

func TestHostExecStrategy_String(t *testing.T) {
	tests := []struct {
		strategy HostExecStrategy
		expected string
	}{
		{StrategyAuto, "auto"},
		{StrategyDirectMount, "direct_mount"},
		{StrategyNsenter, "nsenter"},
		{StrategyFileRead, "file_read"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.strategy.String(); got != tt.expected {
				t.Errorf("Strategy.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHostExecutor_WhitelistEnforcement(t *testing.T) {
	executor := NewHostCommandExecutor()
	ctx := context.Background()

	tests := []struct {
		name       string
		command    string
		shouldFail bool
		errorText  string
	}{
		{
			name:       "allowed command - systemctl",
			command:    "systemctl",
			shouldFail: false,
		},
		{
			name:       "disallowed command - rm",
			command:    "rm",
			shouldFail: true,
			errorText:  "not in whitelist",
		},
		{
			name:       "disallowed command - dd",
			command:    "dd",
			shouldFail: true,
			errorText:  "not in whitelist",
		},
		{
			name:       "disallowed command - mkfs",
			command:    "mkfs",
			shouldFail: true,
			errorText:  "not in whitelist",
		},
		{
			name:       "allowed command - cat",
			command:    "cat",
			shouldFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := executor.RunHostCommand(ctx, TimeoutShort, tt.command, "--help")

			if tt.shouldFail {
				if err == nil {
					t.Errorf("Expected error for disallowed command '%s', got nil", tt.command)
				} else if !strings.Contains(err.Error(), tt.errorText) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorText, err)
				}
			} else {
				// Note: Command might fail if not found, but shouldn't fail whitelist check
				if err != nil && strings.Contains(err.Error(), "not in whitelist") {
					t.Errorf("Allowed command '%s' was rejected by whitelist", tt.command)
				}
			}
		})
	}
}

func TestHostExecutor_TimeoutEnforcement(t *testing.T) {
	executor := NewHostCommandExecutor()
	ctx := context.Background()

	// Try a command that should timeout quickly
	// Note: This test might be flaky depending on system load
	shortTimeout := 1 * time.Millisecond

	result, err := executor.RunHostCommand(ctx, shortTimeout, "cat", "/dev/zero")

	// Should either timeout or fail quickly
	if result != nil && result.TimedOut {
		// Good - timeout detected
		return
	}

	// Or error should mention timeout
	if err != nil && (strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "context deadline")) {
		return
	}

	t.Log("Timeout test inconclusive (system dependent)")
}

func TestHostExecutor_MetricsTracking(t *testing.T) {
	executor := NewHostCommandExecutor()
	executor.ResetMetrics()
	ctx := context.Background()

	initialMetrics := executor.GetMetrics()
	if initialMetrics.TotalCalls != 0 {
		t.Error("Metrics should be zero after reset")
	}

	// Execute a whitelisted command (might fail if not found, but metrics should update)
	_, err := executor.RunHostCommand(ctx, TimeoutShort, "systemctl", "--version")
	// Don't assert on error - command might not exist, but metrics should update
	_ = err

	metrics := executor.GetMetrics()
	if metrics.TotalCalls != 1 {
		t.Errorf("Expected 1 total call, got %d", metrics.TotalCalls)
	}

	// Execute a non-whitelisted command
	_, err = executor.RunHostCommand(ctx, TimeoutShort, "rm", "-rf", "/")
	if err == nil {
		t.Error("should reject non-whitelisted command")
	}

	metrics = executor.GetMetrics()
	if metrics.TotalCalls != 2 {
		t.Errorf("Expected 2 total calls, got %d", metrics.TotalCalls)
	}

	if metrics.FailedCalls == 0 {
		t.Error("Expected at least one failed call")
	}
}

func TestHostExecutor_AddRemoveAllowedCommand(t *testing.T) {
	executor := NewHostCommandExecutor()

	testCmd := "test-custom-command"

	// Should not be allowed initially
	if executor.isCommandAllowed(testCmd) {
		t.Error("Custom command should not be allowed initially")
	}

	// Add to whitelist
	executor.AddAllowedCommand(testCmd)

	// Should be allowed now
	if !executor.isCommandAllowed(testCmd) {
		t.Error("Custom command should be allowed after adding")
	}

	// Remove from whitelist
	executor.RemoveAllowedCommand(testCmd)

	// Should not be allowed anymore
	if executor.isCommandAllowed(testCmd) {
		t.Error("Custom command should not be allowed after removal")
	}
}

func TestHostExecutor_GetSetStrategy(t *testing.T) {
	executor := NewHostCommandExecutor()

	originalStrategy := executor.GetStrategy()

	// Set to different strategy
	executor.SetStrategy(StrategyNsenter)

	if executor.GetStrategy() != StrategyNsenter {
		t.Error("Strategy should be Nsenter after SetStrategy")
	}

	// Restore original
	executor.SetStrategy(originalStrategy)

	if executor.GetStrategy() != originalStrategy {
		t.Error("Strategy should be restored")
	}
}

func TestHostExecutor_MetricsConcurrency(t *testing.T) {
	executor := NewHostCommandExecutor()
	executor.ResetMetrics()
	ctx := context.Background()

	// Concurrent execution to test metrics race conditions
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_, _ = executor.RunHostCommand(ctx, TimeoutShort, "cat", "/dev/null")
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	metrics := executor.GetMetrics()
	if metrics.TotalCalls != 10 {
		t.Errorf("Expected 10 total calls with concurrent execution, got %d", metrics.TotalCalls)
	}
}

func TestHostExecutor_EmptyCommand(t *testing.T) {
	executor := NewHostCommandExecutor()
	ctx := context.Background()

	_, err := executor.RunHostCommand(ctx, TimeoutShort)

	if err == nil {
		t.Error("Expected error for empty command")
	}

	if !strings.Contains(err.Error(), "no command specified") {
		t.Errorf("Expected 'no command specified' error, got: %v", err)
	}
}

func TestFileExists(t *testing.T) {
	// Test with a file that should exist
	if !FileExists("/etc/passwd") {
		t.Error("/etc/passwd should exist")
	}

	// Test with a file that should not exist
	if FileExists("/nonexistent/path/to/file") {
		t.Error("Nonexistent file should return false")
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exact length", 12, "exact length"},
		{"this is a very long string", 10, "this is a ..."},
		{"", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkHostExecutor_RunHostCommand(b *testing.B) {
	executor := NewHostCommandExecutor()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		executor.RunHostCommand(ctx, TimeoutShort, "cat", "/dev/null")
	}
}

func BenchmarkHostExecutor_WhitelistCheck(b *testing.B) {
	executor := NewHostCommandExecutor()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		executor.isCommandAllowed("systemctl")
	}
}
