package output

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewFormatter(t *testing.T) {
	f := NewFormatter("json", true, false)
	if f == nil {
		t.Fatal("NewFormatter returned nil")
	}

	if f.format != "json" {
		t.Errorf("format = %s, want json", f.format)
	}

	if !f.aiMode {
		t.Error("aiMode should be true")
	}
}

func TestFormatReport_Basic(t *testing.T) {
	f := NewFormatter("text", false, false)

	rawReport := map[string]interface{}{
		"hostname": "test-server",
		"firewall": map[string]interface{}{
			"active": true,
		},
		"ssh": map[string]interface{}{
			"permit_root_login": "no",
		},
	}

	report := f.FormatReport(rawReport)

	if report.Hostname != "test-server" {
		t.Errorf("Hostname = %s, want test-server", report.Hostname)
	}

	// Should have at least one positive (firewall, ssh, or other active check)
	if len(report.Positives) < 1 {
		t.Errorf("Expected at least 1 positive, got %d", len(report.Positives))
	}

	// Score should be good (no negatives from this config)
	if report.Score.Value < 80 {
		t.Errorf("Score = %d, expected >= 80 for healthy config", report.Score.Value)
	}

	if report.TrafficLight.Status != StatusGreen {
		t.Errorf("TrafficLight.Status = %s, want %s", report.TrafficLight.Status, StatusGreen)
	}
}

func TestFormatReport_WithIssues(t *testing.T) {
	f := NewFormatter("text", false, false)

	rawReport := map[string]interface{}{
		"hostname": "test-server",
		"firewall": map[string]interface{}{
			"active": false, // Issue: firewall disabled
		},
		"ssh": map[string]interface{}{
			"permit_root_login": "yes", // Issue: root login enabled
		},
		"fail2ban": map[string]interface{}{
			"active": false, // Issue: fail2ban not active
		},
	}

	report := f.FormatReport(rawReport)

	// Should have negatives
	if len(report.Negatives) < 2 {
		t.Errorf("Expected at least 2 negatives, got %d", len(report.Negatives))
	}

	// Score should be lower
	if report.Score.Value >= 80 {
		t.Errorf("Score = %d, expected < 80 for issues", report.Score.Value)
	}

	// Should not be green
	if report.TrafficLight.Status == StatusGreen {
		t.Error("TrafficLight should not be green with issues")
	}
}

func TestFormatReport_CriticalIssues(t *testing.T) {
	f := NewFormatter("text", false, false)

	rawReport := map[string]interface{}{
		"hostname": "test-server",
		"analysis": map[string]interface{}{
			"issues": []interface{}{
				map[string]interface{}{
					"severity": "critical",
					"message":  "Critical security issue",
				},
			},
		},
	}

	report := f.FormatReport(rawReport)

	// Should be red for critical issues
	if report.TrafficLight.Status != StatusRed {
		t.Errorf("TrafficLight.Status = %s, want %s", report.TrafficLight.Status, StatusRed)
	}
}

func TestFormatReport_AIMode(t *testing.T) {
	// Without AI mode
	fNoAI := NewFormatter("text", false, false)
	rawReport := map[string]interface{}{
		"hostname": "test-server",
		"firewall": map[string]interface{}{
			"active": false,
		},
	}

	reportNoAI := fNoAI.FormatReport(rawReport)
	if len(reportNoAI.Advice) > 0 {
		t.Error("Advice should be empty without AI mode")
	}

	// With AI mode
	fAI := NewFormatter("text", true, false)
	reportAI := fAI.FormatReport(rawReport)
	if len(reportAI.Advice) == 0 {
		t.Error("Advice should not be empty with AI mode")
	}
}

func TestCalculateScore(t *testing.T) {
	f := NewFormatter("text", false, false)

	tests := []struct {
		baseScore int
		wantGrade string
	}{
		{95, "A"},
		{85, "B"},
		{75, "C"},
		{65, "D"},
		{50, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		score := f.calculateScore(tt.baseScore, nil)
		if score.Grade != tt.wantGrade {
			t.Errorf("calculateScore(%d).Grade = %s, want %s", tt.baseScore, score.Grade, tt.wantGrade)
		}
		if score.Value != tt.baseScore {
			t.Errorf("calculateScore(%d).Value = %d, want %d", tt.baseScore, score.Value, tt.baseScore)
		}
	}
}

func TestDetermineTrafficLight(t *testing.T) {
	f := NewFormatter("text", false, false)

	tests := []struct {
		name      string
		score     int
		negatives []NegativeItem
		want      string
	}{
		{
			name:      "green_high_score",
			score:     90,
			negatives: nil,
			want:      StatusGreen,
		},
		{
			name:      "yellow_medium_score",
			score:     65,
			negatives: nil,
			want:      StatusYellow,
		},
		{
			name:      "red_low_score",
			score:     40,
			negatives: nil,
			want:      StatusRed,
		},
		{
			name:  "red_with_critical",
			score: 80,
			negatives: []NegativeItem{
				{Severity: "critical", Message: "test"},
			},
			want: StatusRed,
		},
		{
			name:  "red_with_high",
			score: 85,
			negatives: []NegativeItem{
				{Severity: "high", Message: "test"},
			},
			want: StatusRed, // High severity issues = RED
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			light := f.determineTrafficLight(tt.score, tt.negatives)
			if light.Status != tt.want {
				t.Errorf("determineTrafficLight() = %s, want %s", light.Status, tt.want)
			}
		})
	}
}

func TestToJSON(t *testing.T) {
	f := NewFormatter("json", false, false)

	report := &StandardReport{
		Timestamp: "2024-01-01T00:00:00Z",
		Hostname:  "test-host",
		TrafficLight: TrafficLightStatus{
			Status: StatusGreen,
			Emoji:  "\U0001F7E2",
			Label:  "GOOD",
		},
		Score: ScoreInfo{
			Value:    95,
			Grade:    "A",
			MaxScore: 100,
		},
		Positives: []string{"Test positive"},
		Negatives: []NegativeItem{},
	}

	// Without raw report
	jsonStr, err := f.ToJSON(report, false)
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}

	// Should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	if parsed["hostname"] != "test-host" {
		t.Errorf("hostname = %v, want test-host", parsed["hostname"])
	}

	// Should not have raw_report
	if _, ok := parsed["raw_report"]; ok {
		t.Error("Should not include raw_report when includeRaw=false")
	}
}

func TestToText(t *testing.T) {
	f := NewFormatter("text", true, true)

	report := &StandardReport{
		Timestamp: "2024-01-01T00:00:00Z",
		Hostname:  "test-host",
		TrafficLight: TrafficLightStatus{
			Status: StatusGreen,
			Emoji:  "\U0001F7E2",
			Label:  "GOOD - System security is healthy",
		},
		Score: ScoreInfo{
			Value:    95,
			Grade:    "A",
			MaxScore: 100,
		},
		Positives: []string{"Firewall is active", "Root login disabled"},
		Negatives: []NegativeItem{},
		Advice:    []string{"Keep system updated"},
	}

	text := f.ToText(report)

	// Check for expected elements
	if !strings.Contains(text, "test-host") {
		t.Error("Text should contain hostname")
	}

	if !strings.Contains(text, "95/100") {
		t.Error("Text should contain score")
	}

	if !strings.Contains(text, "Grade: A") {
		t.Error("Text should contain grade")
	}

	if !strings.Contains(text, "WHAT'S WORKING WELL") {
		t.Error("Text should contain positives section")
	}

	if !strings.Contains(text, "RECOMMENDATIONS") {
		t.Error("Text should contain recommendations section (AI mode)")
	}
}

func TestToSummary(t *testing.T) {
	f := NewFormatter("summary", false, false)

	report := &StandardReport{
		Hostname: "test-host",
		TrafficLight: TrafficLightStatus{
			Status: StatusYellow,
			Emoji:  "\U0001F7E1",
			Label:  "WARNING",
		},
		Score: ScoreInfo{
			Value: 65,
			Grade: "D",
		},
		Negatives: []NegativeItem{
			{Severity: "high", Message: "test1"},
			{Severity: "medium", Message: "test2"},
		},
	}

	summary := f.ToSummary(report)

	if !strings.Contains(summary, "test-host") {
		t.Error("Summary should contain hostname")
	}

	if !strings.Contains(summary, "65/100") {
		t.Error("Summary should contain score")
	}

	if !strings.Contains(summary, "2 issues") {
		t.Error("Summary should contain issue count")
	}
}

func TestGetExitCode(t *testing.T) {
	f := NewFormatter("text", false, false)

	tests := []struct {
		status   string
		wantCode int
	}{
		{StatusGreen, 0},
		{StatusYellow, 1},
		{StatusRed, 2},
	}

	for _, tt := range tests {
		report := &StandardReport{
			TrafficLight: TrafficLightStatus{Status: tt.status},
		}
		code := f.GetExitCode(report)
		if code != tt.wantCode {
			t.Errorf("GetExitCode(%s) = %d, want %d", tt.status, code, tt.wantCode)
		}
	}
}

func TestGenerateAdvice(t *testing.T) {
	f := NewFormatter("text", true, false)

	negatives := []NegativeItem{
		{Category: "firewall", Severity: "high", Message: "Firewall disabled"},
		{Category: "ssh", Severity: "high", Message: "Root login enabled"},
		{Category: "intrusion_prevention", Severity: "medium", Message: "Fail2ban not active"},
	}

	advice := f.generateAdvice(negatives)

	// Should have advice for each category
	if len(advice) < 2 {
		t.Errorf("Expected at least 2 advice items, got %d", len(advice))
	}

	// Should contain ufw advice
	hasUFWAdvice := false
	for _, a := range advice {
		if strings.Contains(a, "ufw") {
			hasUFWAdvice = true
			break
		}
	}
	if !hasUFWAdvice {
		t.Error("Advice should contain UFW recommendation for firewall issue")
	}
}
