package alertcodes

import (
	"github.com/girste/chihuaudit/internal/analyzers"
)

// Analyzer prefixes for alert codes
var analyzerPrefixes = map[string]string{
	"firewall":  "FW",
	"ssh":       "SSH",
	"services":  "SVC",
	"users":     "USR",
	"docker":    "DOC",
	"fail2ban":  "F2B",
	"updates":   "UPD",
	"kernel":    "KRN",
	"disk":      "DSK",
	"mac":       "MAC",
	"ssl":       "SSL",
	"threats":   "THR",
	"cve":       "CVE",
}

// GetPrefix returns the alert code prefix for an analyzer
func GetPrefix(analyzerName string) string {
	if prefix, ok := analyzerPrefixes[analyzerName]; ok {
		return prefix
	}
	return "UNK" // Unknown analyzer
}

// SeverityFromChange determines severity based on change type and analyzer
func SeverityFromChange(analyzerName string, field string, changeType string) analyzers.Severity {
	// High-risk analyzers - any change is critical
	highRiskAnalyzers := map[string]bool{
		"firewall": true,
		"ssh":      true,
		"users":    true,
	}

	if highRiskAnalyzers[analyzerName] {
		if changeType == "added" || changeType == "removed" {
			return analyzers.SeverityCritical
		}
		return analyzers.SeverityHigh
	}

	// Medium-risk analyzers
	mediumRiskAnalyzers := map[string]bool{
		"services": true,
		"docker":   true,
		"fail2ban": true,
		"mac":      true,
	}

	if mediumRiskAnalyzers[analyzerName] {
		if changeType == "added" || changeType == "removed" {
			return analyzers.SeverityHigh
		}
		return analyzers.SeverityMedium
	}

	// Low-risk analyzers (informational changes)
	if changeType == "added" || changeType == "removed" {
		return analyzers.SeverityMedium
	}

	return analyzers.SeverityLow
}
