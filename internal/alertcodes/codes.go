package alertcodes

import (
	"fmt"
	"sync"

	"github.com/girste/chihuaudit/internal/analyzers"
	"github.com/girste/chihuaudit/internal/baseline"
	"github.com/girste/chihuaudit/internal/recommendations"
)

// Alert represents an alert with a unique code
type Alert struct {
	Code           string             `json:"code" yaml:"code"`
	Severity       analyzers.Severity `json:"severity" yaml:"severity"`
	Analyzer       string             `json:"analyzer" yaml:"analyzer"`
	Message        string             `json:"message" yaml:"message"`
	Field          string             `json:"field" yaml:"field"`
	ChangeType     string             `json:"change_type" yaml:"change_type"`
	Before         interface{}        `json:"before,omitempty" yaml:"before,omitempty"`
	After          interface{}        `json:"after,omitempty" yaml:"after,omitempty"`
	Recommendation string             `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
}

// CodeGenerator generates sequential alert codes per analyzer
type CodeGenerator struct {
	mu       sync.Mutex
	counters map[string]int
}

// NewCodeGenerator creates a new code generator
func NewCodeGenerator() *CodeGenerator {
	return &CodeGenerator{
		counters: make(map[string]int),
	}
}

// Generate creates an alert code for the given analyzer
func (cg *CodeGenerator) Generate(analyzerName string) string {
	cg.mu.Lock()
	defer cg.mu.Unlock()

	prefix := GetPrefix(analyzerName)
	cg.counters[analyzerName]++
	return fmt.Sprintf("%s-%03d", prefix, cg.counters[analyzerName])
}

// Reset resets the counter for an analyzer
func (cg *CodeGenerator) Reset(analyzerName string) {
	cg.mu.Lock()
	defer cg.mu.Unlock()
	cg.counters[analyzerName] = 0
}

// ResetAll resets all counters
func (cg *CodeGenerator) ResetAll() {
	cg.mu.Lock()
	defer cg.mu.Unlock()
	cg.counters = make(map[string]int)
}

// GenerateAlerts converts drifts to alerts with codes.
// riskMap maps analyzer name → risk level ("high", "medium", "low");
// see config.DefaultAnalyzerRiskMap() for defaults.
func GenerateAlerts(drifts []baseline.Drift, riskMap map[string]string) []Alert {
	cg := NewCodeGenerator()
	alerts := make([]Alert, 0, len(drifts))

	for _, drift := range drifts {
		code := cg.Generate(drift.Analyzer)
		severity := SeverityFromChange(drift.Analyzer, drift.Field, string(drift.ChangeType), riskMap)

		alert := Alert{
			Code:           code,
			Severity:       severity,
			Analyzer:       drift.Analyzer,
			Message:        drift.Message,
			Field:          drift.Field,
			ChangeType:     string(drift.ChangeType),
			Before:         drift.Before,
			After:          drift.After,
			Recommendation: recommendations.ForDrift(drift.Analyzer, drift.Field, string(drift.ChangeType)),
		}

		alerts = append(alerts, alert)
	}

	return alerts
}
