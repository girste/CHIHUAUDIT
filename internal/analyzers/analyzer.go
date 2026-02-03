package analyzers

import (
	"context"
	"time"

	"github.com/girste/chihuaudit/internal/config"
)

// Severity levels for issues
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Issue represents a security issue found by an analyzer
type Issue struct {
	Severity       Severity `json:"severity"`
	Message        string   `json:"message"`
	Recommendation string   `json:"recommendation,omitempty"`
}

// Result represents an analyzer's output
type Result struct {
	Installed *bool                  `json:"installed,omitempty"`
	Active    *bool                  `json:"active,omitempty"`
	Checked   bool                   `json:"checked"`
	Issues    []Issue                `json:"issues,omitempty"`
	Data      map[string]interface{} `json:"-"` // Custom fields, marshaled separately
}

// Analyzer is the interface all analyzers must implement
type Analyzer interface {
	Name() string
	RequiresSudo() bool
	Timeout() time.Duration
	Analyze(ctx context.Context, cfg *config.Config) (*Result, error)
}

// Registry manages all analyzers
type Registry struct {
	analyzers map[string]Analyzer
}

// NewRegistry creates a new analyzer registry
func NewRegistry() *Registry {
	return &Registry{
		analyzers: make(map[string]Analyzer),
	}
}

// Register adds an analyzer to the registry
func (r *Registry) Register(a Analyzer) {
	r.analyzers[a.Name()] = a
}

// Get retrieves an analyzer by name
func (r *Registry) Get(name string) (Analyzer, bool) {
	a, ok := r.analyzers[name]
	return a, ok
}

// All returns all registered analyzers
func (r *Registry) All() []Analyzer {
	analyzers := make([]Analyzer, 0, len(r.analyzers))
	for _, a := range r.analyzers {
		analyzers = append(analyzers, a)
	}
	return analyzers
}

// NewIssue creates a new issue with the specified severity and message
func NewIssue(severity Severity, message, recommendation string) Issue {
	return Issue{
		Severity:       severity,
		Message:        message,
		Recommendation: recommendation,
	}
}

// NewResult creates a new result
func NewResult() *Result {
	return &Result{
		Checked: true,
		Issues:  []Issue{},
		Data:    make(map[string]interface{}),
	}
}

// AddIssue adds an issue to the result
func (r *Result) AddIssue(issue Issue) {
	r.Issues = append(r.Issues, issue)
}

// SetInstalled sets the installed status
func (r *Result) SetInstalled(installed bool) {
	r.Installed = &installed
}

// SetActive sets the active status
func (r *Result) SetActive(active bool) {
	r.Active = &active
}
