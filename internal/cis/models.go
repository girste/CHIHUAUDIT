package cis

import (
	"math"
	"time"
)

// ComplianceStatus represents the status of a CIS control check
type ComplianceStatus string

const (
	StatusPass ComplianceStatus = "pass"
	StatusFail ComplianceStatus = "fail"
	StatusNA   ComplianceStatus = "not-applicable"
)

// CISControl represents a single CIS benchmark control (internal, full data)
type CISControl struct {
	ID           string           `json:"id"`
	Title        string           `json:"title"`
	Section      string           `json:"section,omitempty"`
	Level        int              `json:"level,omitempty"`
	Scored       bool             `json:"scored,omitempty"`
	Status       ComplianceStatus `json:"status,omitempty"`
	Evidence     string           `json:"evidence,omitempty"`
	Remediation  string           `json:"remediation,omitempty"`
	AuditCommand string           `json:"audit_command,omitempty"`
}

// FailedControl represents a failed control in compact output format
type FailedControl struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"fix"`
}

// SectionSummary represents section stats in compact format
type SectionSummary struct {
	Name   string  `json:"name"`
	Passed int     `json:"pass"`
	Total  int     `json:"total"`
	Pct    float64 `json:"pct"`
}

// CISResult represents the complete CIS audit result (compact output)
type CISResult struct {
	Benchmark string                    `json:"benchmark"`
	Level     int                       `json:"level"`
	Timestamp string                    `json:"ts"`
	Summary   *ResultSummary            `json:"summary"`
	Sections  map[string]SectionSummary `json:"sections"`
	Failed    []FailedControl           `json:"failed"`
	// Full data only when requested
	AllControls []CISControl `json:"all_controls,omitempty"`
}

// ResultSummary contains the main compliance metrics
type ResultSummary struct {
	Total  int     `json:"total"`
	Passed int     `json:"pass"`
	Failed int     `json:"fail"`
	NA     int     `json:"na"`
	Pct    float64 `json:"pct"`
}

// CheckFunc is the function signature for control checkers
type CheckFunc func() (ComplianceStatus, string)

// ControlDefinition holds the static definition and checker for a control
type ControlDefinition struct {
	Control CISControl
	Check   CheckFunc
}

// NewCISResult creates a new CIS result with current timestamp
func NewCISResult(benchmark string, level int) *CISResult {
	return &CISResult{
		Benchmark: benchmark,
		Level:     level,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Summary:   &ResultSummary{},
		Sections:  make(map[string]SectionSummary),
		Failed:    []FailedControl{},
	}
}

// roundPct rounds percentage to 1 decimal place
func roundPct(pct float64) float64 {
	return math.Round(pct*10) / 10
}
