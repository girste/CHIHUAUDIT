package output

import (
	"encoding/json"
	"testing"
)

func TestConvertToStructured(t *testing.T) {
	// Create a sample StandardReport
	oldReport := &StandardReport{
		Hostname: "test-host",
		TrafficLight: TrafficLightStatus{
			Status: "green",
			Label:  "System is secure",
		},
		Score: ScoreInfo{
			Value: 85,
			Grade: "B",
		},
		Positives: []string{
			"Firewall is active",
			"Root SSH login is disabled",
		},
		Negatives: []NegativeItem{
			{
				Severity: "high",
				Category: "ssh",
				Message:  "SSH password authentication enabled",
			},
		},
	}

	// Convert to structured format
	result := ConvertToStructured(oldReport)

	// Verify basic fields
	if result.SchemaVersion != "1.0" {
		t.Errorf("SchemaVersion = %q, want \"1.0\"", result.SchemaVersion)
	}

	if result.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want \"test-host\"", result.Hostname)
	}

	// Verify status
	if result.Status.Level != "green" {
		t.Errorf("Status.Level = %q, want \"green\"", result.Status.Level)
	}

	if result.Status.Score != 85 {
		t.Errorf("Status.Score = %d, want 85", result.Status.Score)
	}

	if result.Status.Grade != "B" {
		t.Errorf("Status.Grade = %q, want \"B\"", result.Status.Grade)
	}

	// Verify checks
	if result.Checks.Total != 3 {
		t.Errorf("Checks.Total = %d, want 3", result.Checks.Total)
	}

	if result.Checks.Passed != 2 {
		t.Errorf("Checks.Passed = %d, want 2", result.Checks.Passed)
	}

	if result.Checks.Failed != 1 {
		t.Errorf("Checks.Failed = %d, want 1", result.Checks.Failed)
	}

	// Verify positives
	if len(result.Positives) == 0 {
		t.Error("Positives map is empty")
	}

	// Verify issues
	if len(result.Issues) != 1 {
		t.Fatalf("Issues count = %d, want 1", len(result.Issues))
	}

	issue := result.Issues[0]
	if issue.Severity != "high" {
		t.Errorf("Issue.Severity = %q, want \"high\"", issue.Severity)
	}

	if issue.Category != "ssh" {
		t.Errorf("Issue.Category = %q, want \"ssh\"", issue.Category)
	}

	if issue.Code == "" {
		t.Error("Issue.Code is empty, should have a code")
	}
}

func TestStructuredReportToJSON(t *testing.T) {
	report := &StructuredReport{
		SchemaVersion: "1.0",
		Hostname:      "test",
		Status: StatusInfo{
			Level: "green",
			Score: 100,
			Grade: "A",
		},
		Checks: ChecksInfo{
			Total:  1,
			Passed: 1,
			Failed: 0,
		},
		Positives: map[string][]string{
			"firewall": {"active"},
		},
		Issues: []Issue{},
	}

	jsonStr, err := report.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	// Verify it's valid JSON
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &decoded); err != nil {
		t.Fatalf("JSON unmarshal error = %v", err)
	}

	// Verify key fields
	if decoded["schema_version"] != "1.0" {
		t.Errorf("schema_version = %v, want \"1.0\"", decoded["schema_version"])
	}

	if decoded["hostname"] != "test" {
		t.Errorf("hostname = %v, want \"test\"", decoded["hostname"])
	}
}

func TestExtractPositiveCode(t *testing.T) {
	tests := []struct {
		name         string
		verbose      string
		wantCategory string
		wantCode     string
	}{
		{
			name:         "firewall active",
			verbose:      "Firewall is active and protecting the system",
			wantCategory: "firewall",
			wantCode:     "active",
		},
		{
			name:         "firewall active short",
			verbose:      "Firewall is active",
			wantCategory: "firewall",
			wantCode:     "active",
		},
		{
			name:         "ssh root disabled",
			verbose:      "Root SSH login is disabled",
			wantCategory: "ssh",
			wantCode:     "root_disabled",
		},
		{
			name:         "ssh key-only",
			verbose:      "SSH password authentication disabled (key-only)",
			wantCategory: "ssh",
			wantCode:     "key_only",
		},
		{
			name:         "fail2ban active",
			verbose:      "Fail2ban is active",
			wantCategory: "fail2ban",
			wantCode:     "active",
		},
		{
			name:         "unknown positive",
			verbose:      "Some unknown positive finding",
			wantCategory: "",
			wantCode:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			category, code := extractPositiveCode(tt.verbose)
			if category != tt.wantCategory {
				t.Errorf("category = %q, want %q", category, tt.wantCategory)
			}
			if code != tt.wantCode {
				t.Errorf("code = %q, want %q", code, tt.wantCode)
			}
		})
	}
}

func TestMapNegativeToCodeAndRemediation(t *testing.T) {
	tests := []struct {
		name            string
		negative        NegativeItem
		wantCode        IssueCode
		wantRemediation string
	}{
		{
			name: "firewall inactive",
			negative: NegativeItem{
				Category: "firewall",
				Message:  "Firewall is not active",
			},
			wantCode:        IssueFirewallInactive,
			wantRemediation: "Enable UFW: ufw enable && ufw default deny",
		},
		{
			name: "ssh root enabled",
			negative: NegativeItem{
				Category: "ssh",
				Message:  "Root SSH login is enabled (security risk)",
			},
			wantCode:        IssueSSHRootEnabled,
			wantRemediation: "Set PermitRootLogin no in sshd_config",
		},
		{
			name: "fail2ban inactive",
			negative: NegativeItem{
				Category: "fail2ban",
				Message:  "Fail2ban is not active (brute-force protection missing)",
			},
			wantCode:        IssueFail2banInactive,
			wantRemediation: "Install: apt install fail2ban",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, remediation := mapNegativeToCodeAndRemediation(tt.negative)
			if code != tt.wantCode {
				t.Errorf("code = %q, want %q", code, tt.wantCode)
			}
			if remediation != tt.wantRemediation {
				t.Errorf("remediation = %q, want %q", remediation, tt.wantRemediation)
			}
		})
	}
}

func TestShortenMessage(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		wantLen int
	}{
		{
			name:    "short message unchanged",
			msg:     "Short message",
			wantLen: len("Short message"),
		},
		{
			name:    "long message truncated",
			msg:     "This is a very long message that exceeds the maximum length and should be truncated to fit within the allowed limit for messages",
			wantLen: 80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shortenMessage(tt.msg)
			if len(result) != tt.wantLen {
				t.Errorf("len(shortenMessage(%q)) = %d, want %d", tt.msg, len(result), tt.wantLen)
			}
		})
	}
}
