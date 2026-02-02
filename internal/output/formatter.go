package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Format types
const (
	FormatJSON    = "json"
	FormatText    = "text"
	FormatSummary = "summary"
	FormatCompact = "compact"
)

// Traffic light status
const (
	StatusGreen  = "green"  // Score 80-100, no critical/high issues
	StatusYellow = "yellow" // Score 50-79, some issues
	StatusRed    = "red"    // Score 0-49, critical issues
)

// StandardReport is the unified output format
type StandardReport struct {
	Timestamp    string             `json:"timestamp"`
	Hostname     string             `json:"hostname"`
	TrafficLight TrafficLightStatus `json:"traffic_light"`
	Score        ScoreInfo          `json:"score"`
	Positives    []string           `json:"positives"`
	Negatives    []NegativeItem     `json:"negatives"`
	Advice       []string           `json:"advice,omitempty"` // Only with AI mode
	RawReport    interface{}        `json:"raw_report,omitempty"`
}

type TrafficLightStatus struct {
	Status string `json:"status"` // green, yellow, red
	Emoji  string `json:"emoji"`  // For CLI/Discord
	Label  string `json:"label"`
}

type ScoreInfo struct {
	Value    int    `json:"value"` // 0-100
	Grade    string `json:"grade"` // A, B, C, D, F
	MaxScore int    `json:"max_score"`
}

type NegativeItem struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Message  string `json:"message"`
}

// Formatter handles output formatting
type Formatter struct {
	aiMode     bool
	format     string
	verbose    bool
	structured bool // Use v1.0 structured format (token-efficient)
}

// NewFormatter creates a new formatter
func NewFormatter(format string, aiMode, verbose bool) *Formatter {
	return &Formatter{
		aiMode:     aiMode,
		format:     format,
		verbose:    verbose,
		structured: false, // Default to old format for CLI compatibility
	}
}

// NewStructuredFormatter creates formatter that outputs v1.0 structured format
func NewStructuredFormatter() *Formatter {
	return &Formatter{
		aiMode:     false,
		format:     FormatJSON,
		verbose:    false,
		structured: true, // Use new token-efficient format
	}
}

// FormatReport converts raw audit report to standardized format
func (f *Formatter) FormatReport(rawReport map[string]interface{}) *StandardReport {
	report := &StandardReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RawReport: rawReport,
	}

	// Extract hostname
	if h, ok := rawReport["hostname"].(string); ok {
		report.Hostname = h
	}

	// Calculate score and extract issues
	positives, negatives, score := f.analyzeReport(rawReport)
	report.Positives = positives
	report.Negatives = negatives
	report.Score = f.calculateScore(score, negatives)
	report.TrafficLight = f.determineTrafficLight(report.Score.Value, negatives)

	// Add advice only in AI mode
	if f.aiMode {
		report.Advice = f.generateAdvice(negatives)
	}

	return report
}

// FormatReportStructured converts raw audit report to v1.0 structured format (token-efficient)
func (f *Formatter) FormatReportStructured(rawReport map[string]interface{}) *StructuredReport {
	// First generate StandardReport
	standardReport := f.FormatReport(rawReport)

	// Convert to StructuredReport
	return ConvertToStructured(standardReport)
}

func (f *Formatter) analyzeReport(report map[string]interface{}) ([]string, []NegativeItem, int) {
	positives := []string{}
	negatives := []NegativeItem{}
	baseScore := 100

	// Analyze firewall
	if fw, ok := report["firewall"].(map[string]interface{}); ok {
		if active, ok := fw["active"].(bool); ok && active {
			positives = append(positives, "Firewall is active and protecting the system")
		} else {
			negatives = append(negatives, NegativeItem{
				Severity: "high",
				Category: "firewall",
				Message:  "Firewall is not active",
			})
			baseScore -= 15
		}
	}

	// Analyze SSH
	if ssh, ok := report["ssh"].(map[string]interface{}); ok {
		if rootLogin, ok := ssh["permit_root_login"].(string); ok && rootLogin == "no" {
			positives = append(positives, "Root SSH login is disabled")
		} else if rootLogin == "yes" {
			negatives = append(negatives, NegativeItem{
				Severity: "high",
				Category: "ssh",
				Message:  "Root SSH login is enabled (security risk)",
			})
			baseScore -= 10
		}

		if passAuth, ok := ssh["password_authentication"].(string); ok && passAuth == "no" {
			positives = append(positives, "SSH password authentication disabled (key-only)")
		}
	}

	// Analyze fail2ban
	if f2b, ok := report["fail2ban"].(map[string]interface{}); ok {
		if active, ok := f2b["active"].(bool); ok && active {
			positives = append(positives, "Fail2ban is active and blocking attacks")
		} else {
			negatives = append(negatives, NegativeItem{
				Severity: "medium",
				Category: "intrusion_prevention",
				Message:  "Fail2ban is not active (brute-force protection missing)",
			})
			baseScore -= 8
		}
	}

	// Analyze MAC (AppArmor/SELinux)
	if mac, ok := report["mac"].(map[string]interface{}); ok {
		if active, ok := mac["active"].(bool); ok && active {
			positives = append(positives, "Mandatory Access Control (AppArmor/SELinux) is active")
		}
	}

	// Analyze Docker
	if docker, ok := report["docker"].(map[string]interface{}); ok {
		if installed, ok := docker["installed"].(bool); ok && installed {
			if rootless, ok := docker["rootless"].(bool); ok && rootless {
				positives = append(positives, "Docker running in rootless mode")
			}
			if privileged, ok := docker["privileged_containers"].(int); ok && privileged > 0 {
				negatives = append(negatives, NegativeItem{
					Severity: "high",
					Category: "containers",
					Message:  fmt.Sprintf("%d privileged container(s) detected", privileged),
				})
				baseScore -= 10
			}
		}
	}

	// Analyze updates
	if updates, ok := report["updates"].(map[string]interface{}); ok {
		if security, ok := updates["security_updates"].(int); ok {
			if security == 0 {
				positives = append(positives, "System is up to date with security patches")
			} else {
				severity := "medium"
				if security > 10 {
					severity = "high"
					baseScore -= 15
				} else {
					baseScore -= 5
				}
				negatives = append(negatives, NegativeItem{
					Severity: severity,
					Category: "updates",
					Message:  fmt.Sprintf("%d security update(s) pending", security),
				})
			}
		}
	}

	// Analyze kernel hardening
	if kernel, ok := report["kernel"].(map[string]interface{}); ok {
		if aslr, ok := kernel["aslr_enabled"].(bool); ok && aslr {
			positives = append(positives, "ASLR (Address Space Layout Randomization) enabled")
		}
	}

	// Check analysis section for additional issues
	if analysis, ok := report["analysis"].(map[string]interface{}); ok {
		if issues, ok := analysis["issues"].([]interface{}); ok {
			for _, issue := range issues {
				if issueMap, ok := issue.(map[string]interface{}); ok {
					sev := "medium"
					if s, ok := issueMap["severity"].(string); ok {
						sev = s
					}
					msg := ""
					if m, ok := issueMap["message"].(string); ok {
						msg = m
					}
					if msg != "" {
						negatives = append(negatives, NegativeItem{
							Severity: sev,
							Category: "analysis",
							Message:  msg,
						})
						switch sev {
						case "critical":
							baseScore -= 25
						case "high":
							baseScore -= 10
						case "medium":
							baseScore -= 5
						}
					}
				}
			}
		}
	}

	if baseScore < 0 {
		baseScore = 0
	}

	return positives, negatives, baseScore
}

func (f *Formatter) calculateScore(baseScore int, negatives []NegativeItem) ScoreInfo {
	score := ScoreInfo{
		Value:    baseScore,
		MaxScore: 100,
	}

	switch {
	case baseScore >= 90:
		score.Grade = "A"
	case baseScore >= 80:
		score.Grade = "B"
	case baseScore >= 70:
		score.Grade = "C"
	case baseScore >= 60:
		score.Grade = "D"
	default:
		score.Grade = "F"
	}

	return score
}

func (f *Formatter) determineTrafficLight(score int, negatives []NegativeItem) TrafficLightStatus {
	// Check for critical/high/medium issues
	hasCritical := false
	hasHigh := false
	hasMedium := false
	for _, neg := range negatives {
		switch neg.Severity {
		case "critical":
			hasCritical = true
		case "high":
			hasHigh = true
		case "medium":
			hasMedium = true
		}
	}

	// RED: critical or high severity issues
	if hasCritical || hasHigh || score < 50 {
		return TrafficLightStatus{
			Status: StatusRed,
			Emoji:  "\U0001F534", // Red circle
			Label:  "CRITICAL - Immediate action required",
		}
	}

	// YELLOW: medium severity or score issues
	if hasMedium || score < 80 {
		return TrafficLightStatus{
			Status: StatusYellow,
			Emoji:  "\U0001F7E1", // Yellow circle
			Label:  "WARNING - Issues need attention",
		}
	}

	// GREEN: all clear
	return TrafficLightStatus{
		Status: StatusGreen,
		Emoji:  "\U0001F7E2", // Green circle
		Label:  "GOOD - System security is healthy",
	}
}

func (f *Formatter) generateAdvice(negatives []NegativeItem) []string {
	advice := []string{}
	seen := make(map[string]bool)

	for _, neg := range negatives {
		var tip string
		switch neg.Category {
		case "firewall":
			tip = "Enable UFW firewall: sudo ufw enable && sudo ufw default deny incoming"
		case "ssh":
			if strings.Contains(neg.Message, "Root") {
				tip = "Disable root SSH: edit /etc/ssh/sshd_config and set PermitRootLogin no"
			}
		case "intrusion_prevention":
			tip = "Install and enable fail2ban: sudo apt install fail2ban && sudo systemctl enable fail2ban"
		case "updates":
			tip = "Apply security updates: sudo apt update && sudo apt upgrade"
		case "containers":
			tip = "Avoid privileged containers. Use --cap-drop=ALL and add only needed capabilities"
		}

		if tip != "" && !seen[tip] {
			advice = append(advice, tip)
			seen[tip] = true
		}
	}

	return advice
}

// ToJSON outputs the report as JSON
func (f *Formatter) ToJSON(report *StandardReport, includeRaw bool) (string, error) {
	output := report
	if !includeRaw {
		output = &StandardReport{
			Timestamp:    report.Timestamp,
			Hostname:     report.Hostname,
			TrafficLight: report.TrafficLight,
			Score:        report.Score,
			Positives:    report.Positives,
			Negatives:    report.Negatives,
			Advice:       report.Advice,
		}
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ToText outputs the report as formatted text
func (f *Formatter) ToText(report *StandardReport) string {
	var sb strings.Builder

	// Header with traffic light
	sb.WriteString("\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	sb.WriteString(fmt.Sprintf("  %s  SECURITY REPORT  -  %s\n", report.TrafficLight.Emoji, report.Hostname))
	sb.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	// Traffic light status
	sb.WriteString(fmt.Sprintf("  Status: %s %s\n", report.TrafficLight.Emoji, report.TrafficLight.Label))
	sb.WriteString(fmt.Sprintf("  Score:  %d/100 (Grade: %s)\n", report.Score.Value, report.Score.Grade))
	sb.WriteString(fmt.Sprintf("  Time:   %s\n\n", report.Timestamp))

	// Positives
	if len(report.Positives) > 0 {
		sb.WriteString("───────────────────────────────────────────────────────────────\n")
		sb.WriteString("  \u2705 WHAT'S WORKING WELL\n")
		sb.WriteString("───────────────────────────────────────────────────────────────\n")
		for _, p := range report.Positives {
			sb.WriteString(fmt.Sprintf("  \u2022 %s\n", p))
		}
		sb.WriteString("\n")
	}

	// Negatives
	if len(report.Negatives) > 0 {
		sb.WriteString("───────────────────────────────────────────────────────────────\n")
		sb.WriteString("  \u26A0\uFE0F  ISSUES REQUIRING ATTENTION\n")
		sb.WriteString("───────────────────────────────────────────────────────────────\n")
		for _, n := range report.Negatives {
			var icon string
			switch n.Severity {
			case "critical":
				icon = "\U0001F6A8" // Siren
			case "high":
				icon = "\U0001F534" // Red circle
			default:
				icon = "\u26A0\uFE0F" // Warning
			}
			sb.WriteString(fmt.Sprintf("  %s [%s] %s\n", icon, strings.ToUpper(n.Severity), n.Message))
		}
		sb.WriteString("\n")
	}

	// Advice (only in AI mode)
	if len(report.Advice) > 0 {
		sb.WriteString("───────────────────────────────────────────────────────────────\n")
		sb.WriteString("  \U0001F4A1 RECOMMENDATIONS\n")
		sb.WriteString("───────────────────────────────────────────────────────────────\n")
		for i, a := range report.Advice {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, a))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("═══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// ToSummary outputs a one-line summary
func (f *Formatter) ToSummary(report *StandardReport) string {
	issueCount := len(report.Negatives)
	return fmt.Sprintf("%s %s | Score: %d/100 (%s) | %d issues | %s",
		report.TrafficLight.Emoji,
		report.Hostname,
		report.Score.Value,
		report.Score.Grade,
		issueCount,
		report.TrafficLight.Label,
	)
}

// GetExitCode returns appropriate exit code based on status
func (f *Formatter) GetExitCode(report *StandardReport) int {
	switch report.TrafficLight.Status {
	case StatusRed:
		return 2 // Critical
	case StatusYellow:
		return 1 // Warning
	default:
		return 0 // OK
	}
}
