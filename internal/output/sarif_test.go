package output

import (
	"testing"
)

func TestConvertToSARIF(t *testing.T) {
	report := &StructuredReport{
		Timestamp: "2024-01-01T00:00:00Z",
		Hostname:  "test-host",
		Checks:    ChecksInfo{Total: 2, Failed: 2},
		Issues: []Issue{
			{Severity: "critical", Category: "firewall", Msg: "Test issue", Code: "FW-001", Remediation: "Fix it"},
			{Severity: "high", Category: "ssh", Msg: "SSH issue", Code: "SSH-001", Remediation: "Fix SSH"},
		},
	}

	sarif := ConvertToSARIF(report, "test-host")
	if sarif == nil {
		t.Fatal("ConvertToSARIF returned nil")
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("Version = %s, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Errorf("Runs length = %d, want 1", len(sarif.Runs))
	}
	if len(sarif.Runs[0].Results) != 2 {
		t.Errorf("Results length = %d, want 2", len(sarif.Runs[0].Results))
	}
}

func TestMapSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		severity string
		level    string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"info", "note"},
		{"unknown", "warning"},
	}

	for _, tt := range tests {
		got := mapSeverityToSARIFLevel(tt.severity)
		if got != tt.level {
			t.Errorf("mapSeverityToSARIFLevel(%s) = %s, want %s", tt.severity, got, tt.level)
		}
	}
}

func TestMapCategoryToLocation(t *testing.T) {
	tests := []struct {
		category string
		hostname string
	}{
		{"firewall", "test-host"},
		{"ssh", "test-host"},
		{"services", "test-host"},
		{"unknown", "test-host"},
	}

	for _, tt := range tests {
		loc := mapCategoryToLocation(tt.category, tt.hostname)
		if loc == nil {
			t.Errorf("mapCategoryToLocation(%s, %s) returned nil", tt.category, tt.hostname)
			continue
		}
		if loc.PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("URI is empty for %s", tt.category)
		}
	}
}

func TestSARIFToJSON(t *testing.T) {
	report := &StructuredReport{
		Timestamp: "2024-01-01T00:00:00Z",
		Hostname:  "test",
		Checks:    ChecksInfo{Total: 1, Failed: 1},
		Issues:    []Issue{{Severity: "high", Category: "test", Msg: "test", Code: "TST-001", Remediation: "Fix"}},
	}

	sarif := ConvertToSARIF(report, "test")
	data, err := sarif.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("ToJSON returned empty data")
	}
}
