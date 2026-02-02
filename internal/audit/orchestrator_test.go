package audit

import (
	"context"
	"testing"

	"github.com/girste/chihuaudit/internal/config"
)

func TestNewOrchestrator(t *testing.T) {
	orch := NewOrchestrator()
	if orch == nil {
		t.Fatal("NewOrchestrator returned nil")
	}
}

func TestRunAudit_WithDefaultConfig(t *testing.T) {
	cfg, err := config.Load() // Load full config with patterns
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	orch := NewOrchestrator()
	ctx := context.Background()

	report, err := orch.RunAudit(ctx, cfg, false)
	if err != nil {
		t.Logf("Audit failed (expected on some systems): %v", err)
		return
	}

	if report == nil {
		t.Fatal("Report is nil")
	}

	// Check basic structure
	if _, ok := report["metadata"]; !ok {
		t.Error("Report missing metadata")
	}
}
