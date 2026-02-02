package system

import (
	"context"
	"testing"
	"time"
)

func TestCommandResult(t *testing.T) {
	result := &CommandResult{
		Stdout:   "test output",
		Stderr:   "",
		ExitCode: 0,
		Success:  true,
		TimedOut: false,
	}

	if result.Stdout != "test output" {
		t.Errorf("Stdout = %q, want 'test output'", result.Stdout)
	}
	if !result.Success {
		t.Error("Success = false, want true")
	}
	if result.TimedOut {
		t.Error("TimedOut = true, want false")
	}
}

func TestTimeoutConstants(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		min     time.Duration
	}{
		{"TimeoutShort", TimeoutShort, 1 * time.Second},
		{"TimeoutMedium", TimeoutMedium, 5 * time.Second},
		{"TimeoutLong", TimeoutLong, 10 * time.Second},
		{"TimeoutVeryLong", TimeoutVeryLong, 60 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.timeout < tt.min {
				t.Errorf("%s = %v, want >= %v", tt.name, tt.timeout, tt.min)
			}
		})
	}
}

func TestRunCommand(t *testing.T) {
	ctx := context.Background()

	t.Run("successful command", func(t *testing.T) {
		result, err := RunCommand(ctx, TimeoutShort, "echo", "hello")
		if err != nil {
			t.Fatalf("RunCommand() error = %v", err)
		}
		if result == nil {
			t.Fatal("RunCommand() returned nil result")
		}
		if !result.Success {
			t.Errorf("Success = false, want true")
		}
		if result.ExitCode != 0 {
			t.Errorf("ExitCode = %d, want 0", result.ExitCode)
		}
	})

	t.Run("no command specified", func(t *testing.T) {
		result, err := RunCommand(ctx, TimeoutShort)
		if err == nil {
			t.Error("RunCommand() with no args should return error")
		}
		if result != nil {
			t.Errorf("RunCommand() returned result = %v, want nil", result)
		}
	})

	t.Run("command timeout", func(t *testing.T) {
		// Command that sleeps longer than timeout
		result, err := RunCommand(ctx, 100*time.Millisecond, "sleep", "10")
		if err == nil {
			t.Error("RunCommand() timeout should return error")
		}
		if result == nil {
			t.Fatal("RunCommand() should return result even on timeout")
		}
		if !result.TimedOut {
			t.Error("TimedOut = false, want true")
		}
	})

	t.Run("command not found", func(t *testing.T) {
		result, err := RunCommand(ctx, TimeoutShort, "nonexistent-command-xyz123")
		if err != nil {
			t.Logf("Expected error for nonexistent command: %v", err)
		}
		if result != nil && result.Success {
			t.Error("Success = true for nonexistent command, want false")
		}
	})

	t.Run("command with arguments", func(t *testing.T) {
		result, err := RunCommand(ctx, TimeoutShort, "echo", "arg1", "arg2", "arg3")
		if err != nil {
			t.Fatalf("RunCommand() error = %v", err)
		}
		if !result.Success {
			t.Errorf("Success = false, want true")
		}
	})
}

func TestRunCommandSudo(t *testing.T) {
	ctx := context.Background()

	t.Run("command without sudo need", func(t *testing.T) {
		result, err := RunCommandSudo(ctx, TimeoutShort, "echo", "test")
		if err != nil {
			t.Fatalf("RunCommandSudo() error = %v", err)
		}
		if result == nil {
			t.Fatal("RunCommandSudo() returned nil result")
		}
		if !result.Success {
			t.Errorf("Success = false, want true")
		}
	})

	t.Run("no command specified", func(t *testing.T) {
		result, err := RunCommandSudo(ctx, TimeoutShort)
		if err == nil {
			t.Error("RunCommandSudo() with no args should return error")
		}
		if result != nil {
			t.Errorf("RunCommandSudo() returned result = %v, want nil", result)
		}
	})
}

func TestCommandExists(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"echo exists", "echo", true},
		{"ls exists", "ls", true},
		{"nonexistent", "nonexistent-cmd-xyz", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CommandExists(tt.command)
			if got != tt.want {
				t.Errorf("CommandExists(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestCommandExistsWithContext(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"echo exists", "echo", true},
		{"ls exists", "ls", true},
		{"nonexistent", "cmd-xyz-does-not-exist", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CommandExistsWithContext(ctx, tt.command)
			if got != tt.want {
				t.Errorf("CommandExistsWithContext(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestIsServiceActive(t *testing.T) {
	ctx := context.Background()

	// Test with likely non-existent service
	result := IsServiceActive(ctx, "nonexistent-service-xyz123")
	if result {
		t.Error("IsServiceActive() = true for nonexistent service, want false")
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result, err := RunCommand(ctx, TimeoutLong, "sleep", "1")

	// Command should fail due to cancelled context
	if result != nil && result.Success {
		t.Error("RunCommand() with cancelled context should not succeed")
	}

	t.Logf("Cancelled context result: err=%v, success=%v", err, result != nil && result.Success)
}
