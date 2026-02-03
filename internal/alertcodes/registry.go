package alertcodes

import (
	"github.com/girste/chihuaudit/internal/analyzers"
)

// analyzerPrefixes maps analyzer names to alert code prefixes.
// To add a new analyzer: register it in orchestrator.go AND add its prefix here.
var analyzerPrefixes = map[string]string{
	"firewall":    "FW",
	"ssh":         "SSH",
	"services":    "SVC",
	"users":       "USR",
	"docker":      "DOC",
	"fail2ban":    "F2B",
	"updates":     "UPD",
	"kernel":      "KRN",
	"disk":        "DSK",
	"mac":         "MAC",
	"ssl":         "SSL",
	"threats":     "THR",
	"sudo":        "SDO",
	"cron":        "CRN",
	"permissions": "PRM",
	"processes":   "PRC",
	"performance": "PER",
}

// GetPrefix returns the alert code prefix for an analyzer.
func GetPrefix(analyzerName string) string {
	if prefix, ok := analyzerPrefixes[analyzerName]; ok {
		return prefix
	}
	return "UNK"
}

// SeverityFromChange determines alert severity based on the analyzer's configured
// risk level and the type of change detected.  Risk levels come from the whitelist
// config (thresholds.analyzerRisk) — nothing is hardcoded here.
//
// Mapping:
//
//	"high"   → added/removed = critical, modified = high
//	"medium" → added/removed = high,     modified = medium
//	default  → added/removed = medium,   modified = low
func SeverityFromChange(analyzerName string, field string, changeType string, riskMap map[string]string) analyzers.Severity {
	risk := riskMap[analyzerName]

	switch risk {
	case "high":
		if changeType == "added" || changeType == "removed" {
			return analyzers.SeverityCritical
		}
		return analyzers.SeverityHigh
	case "medium":
		if changeType == "added" || changeType == "removed" {
			return analyzers.SeverityHigh
		}
		return analyzers.SeverityMedium
	default: // "low" or unmapped
		if changeType == "added" || changeType == "removed" {
			return analyzers.SeverityMedium
		}
		return analyzers.SeverityLow
	}
}
