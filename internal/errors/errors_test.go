package errors

import (
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"ErrAnalyzerFailed", ErrAnalyzerFailed, "analyzer failed"},
		{"ErrTimeoutExceeded", ErrTimeoutExceeded, "timeout exceeded"},
		{"ErrPermissionDenied", ErrPermissionDenied, "permission denied"},
		{"ErrCommandNotFound", ErrCommandNotFound, "command not found"},
		{"ErrInvalidConfig", ErrInvalidConfig, "invalid configuration"},
		{"ErrNetworkFailure", ErrNetworkFailure, "network failure"},
		{"ErrInvalidInput", ErrInvalidInput, "invalid input"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error message = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWrap(t *testing.T) {
	t.Run("wrap nil error", func(t *testing.T) {
		got := Wrap(nil, "context")
		if got != nil {
			t.Errorf("Wrap(nil) = %v, want nil", got)
		}
	})

	t.Run("wrap simple error", func(t *testing.T) {
		got := Wrap(ErrAnalyzerFailed, "failed to analyze firewall")
		if got == nil {
			t.Fatal("Wrap() = nil, want error")
		}
		want := "failed to analyze firewall: analyzer failed"
		if got.Error() != want {
			t.Errorf("Wrap() = %v, want %v", got.Error(), want)
		}
		if !Is(got, ErrAnalyzerFailed) {
			t.Error("Wrap() broke error chain")
		}
	})

	t.Run("wrap with args", func(t *testing.T) {
		got := Wrap(ErrTimeoutExceeded, "command %s timed out after %d seconds", "ufw", 30)
		want := "command ufw timed out after 30 seconds: timeout exceeded"
		if got.Error() != want {
			t.Errorf("Wrap() = %v, want %v", got.Error(), want)
		}
	})
}

func TestNew(t *testing.T) {
	t.Run("simple message", func(t *testing.T) {
		got := New("something went wrong")
		if got.Error() != "something went wrong" {
			t.Errorf("New() = %v, want 'something went wrong'", got.Error())
		}
	})

	t.Run("formatted message", func(t *testing.T) {
		got := New("failed to process %s with code %d", "request", 500)
		want := "failed to process request with code 500"
		if got.Error() != want {
			t.Errorf("New() = %v, want %v", got.Error(), want)
		}
	})
}

func TestIs(t *testing.T) {
	wrapped := Wrap(ErrAnalyzerFailed, "context")

	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{"same error", ErrAnalyzerFailed, ErrAnalyzerFailed, true},
		{"different error", ErrAnalyzerFailed, ErrTimeoutExceeded, false},
		{"wrapped error", wrapped, ErrAnalyzerFailed, true},
		{"nil error", nil, ErrAnalyzerFailed, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Is(tt.err, tt.target); got != tt.want {
				t.Errorf("Is() = %v, want %v", got, tt.want)
			}
		})
	}
}
