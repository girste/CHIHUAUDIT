package analyzers

import (
	"context"
	"time"

	"github.com/girste/mcp-cybersec-watchdog/internal/config"
	"github.com/girste/mcp-cybersec-watchdog/internal/system"
)

type CVEAnalyzer struct{}

func (a *CVEAnalyzer) Name() string           { return "cve" }
func (a *CVEAnalyzer) RequiresSudo() bool     { return false }
func (a *CVEAnalyzer) Timeout() time.Duration { return system.TimeoutMedium }

func (a *CVEAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	// Simplified version
	result.Data = map[string]interface{}{
		"vulnerabilitiesFound": 0,
		"criticalCount":        0,
		"highCount":            0,
	}

	return result, nil
}
