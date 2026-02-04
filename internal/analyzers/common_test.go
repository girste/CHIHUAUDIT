package analyzers

import (
	"testing"
)

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			if string(tt.severity) != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, string(tt.severity))
			}
		})
	}
}

func TestIssueStruct(t *testing.T) {
	issue := Issue{
		Severity:       SeverityCritical,
		Message:        "test issue",
		Recommendation: "fix it",
	}

	if issue.Severity != SeverityCritical {
		t.Errorf("Expected critical severity, got %s", issue.Severity)
	}
	if issue.Message != "test issue" {
		t.Error("Message mismatch")
	}
	if issue.Recommendation != "fix it" {
		t.Error("Recommendation mismatch")
	}
}

func TestResultStruct(t *testing.T) {
	installed := true
	active := true

	result := Result{
		Installed: &installed,
		Active:    &active,
		Checked:   true,
		Issues: []Issue{
			{Severity: SeverityHigh, Message: "test"},
		},
		Data: map[string]interface{}{
			"test_key": "test_value",
		},
	}

	if !*result.Installed {
		t.Error("Installed should be true")
	}
	if !*result.Active {
		t.Error("Active should be true")
	}
	if !result.Checked {
		t.Error("Checked should be true")
	}
	if len(result.Issues) != 1 {
		t.Errorf("Expected 1 issue, got %d", len(result.Issues))
	}
	if result.Data["test_key"] != "test_value" {
		t.Error("Data mismatch")
	}
}

func TestResultWithoutIssues(t *testing.T) {
	result := Result{
		Checked: true,
		Issues:  []Issue{},
	}

	if len(result.Issues) != 0 {
		t.Errorf("Expected 0 issues, got %d", len(result.Issues))
	}
	if !result.Checked {
		t.Error("Checked should be true")
	}
}

func TestSeverityComparison(t *testing.T) {
	if SeverityCritical == SeverityLow {
		t.Error("Critical and Low should be different")
	}
	if SeverityHigh == SeverityMedium {
		t.Error("High and Medium should be different")
	}
}

func TestIssueWithoutRecommendation(t *testing.T) {
	issue := Issue{
		Severity: SeverityMedium,
		Message:  "test",
	}

	if issue.Recommendation != "" {
		t.Error("Recommendation should be empty")
	}
	if issue.Severity != SeverityMedium {
		t.Error("Severity mismatch")
	}
}

func TestResultMultipleIssues(t *testing.T) {
	result := Result{
		Checked: true,
		Issues: []Issue{
			{Severity: SeverityCritical, Message: "critical issue"},
			{Severity: SeverityHigh, Message: "high issue"},
			{Severity: SeverityMedium, Message: "medium issue"},
		},
	}

	if len(result.Issues) != 3 {
		t.Errorf("Expected 3 issues, got %d", len(result.Issues))
	}
	if result.Issues[0].Severity != SeverityCritical {
		t.Error("First issue should be critical")
	}
}

func TestNewRegistry(t *testing.T) {
	registry := NewRegistry()
	if registry == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if registry.analyzers == nil {
		t.Error("Analyzers map not initialized")
	}
}
