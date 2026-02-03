package alertcodes

import (
	"testing"

	"github.com/girste/chihuaudit/internal/analyzers"
)

func TestNewCodeGenerator(t *testing.T) {
	cg := NewCodeGenerator()
	if cg == nil {
		t.Fatal("NewCodeGenerator returned nil")
	}
	if cg.counters == nil {
		t.Error("counters map not initialized")
	}
}

func TestCodeGenerator_Generate(t *testing.T) {
	cg := NewCodeGenerator()

	tests := []struct {
		analyzer     string
		expectedCode string
	}{
		{"firewall", "FW-001"},
		{"ssh", "SSH-001"},
		{"services", "SVC-001"},
		{"firewall", "FW-002"},
		{"ssh", "SSH-002"},
	}

	for _, tt := range tests {
		t.Run(tt.analyzer, func(t *testing.T) {
			code := cg.Generate(tt.analyzer)
			if code != tt.expectedCode {
				t.Errorf("Expected %s, got %s", tt.expectedCode, code)
			}
		})
	}
}

func TestCodeGenerator_Reset(t *testing.T) {
	cg := NewCodeGenerator()

	// Generate some codes
	cg.Generate("firewall")
	cg.Generate("firewall")
	
	if cg.counters["firewall"] != 2 {
		t.Errorf("Expected counter 2, got %d", cg.counters["firewall"])
	}

	// Reset
	cg.Reset("firewall")
	
	if cg.counters["firewall"] != 0 {
		t.Errorf("Expected counter 0 after reset, got %d", cg.counters["firewall"])
	}

	// Next code should be 001 again
	code := cg.Generate("firewall")
	if code != "FW-001" {
		t.Errorf("Expected FW-001 after reset, got %s", code)
	}
}

func TestCodeGenerator_Concurrent(t *testing.T) {
	cg := NewCodeGenerator()
	done := make(chan bool)

	// Run multiple goroutines generating codes
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				cg.Generate("test")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have generated 1000 codes
	if cg.counters["test"] != 1000 {
		t.Errorf("Expected 1000 codes, got %d", cg.counters["test"])
	}
}

func TestAlert_Struct(t *testing.T) {
	alert := Alert{
		Code:           "FW-001",
		Severity:       analyzers.SeverityCritical,
		Analyzer:       "firewall",
		Message:        "Test message",
		Field:          "test_field",
		ChangeType:     "added",
		Before:         "old",
		After:          "new",
		Recommendation: "Fix it",
	}

	if alert.Code != "FW-001" {
		t.Errorf("Expected code FW-001, got %s", alert.Code)
	}
	if alert.Severity != analyzers.SeverityCritical {
		t.Errorf("Expected critical severity, got %s", alert.Severity)
	}
	if alert.Message == "" {
		t.Error("Message should not be empty")
	}
}

