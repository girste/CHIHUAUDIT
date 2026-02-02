// Package output provides SARIF 2.1.0 format converter.
// SARIF (Static Analysis Results Interchange Format) is a standard
// JSON format for security findings, used by GitHub/GitLab Code Scanning.
package output

import (
	"encoding/json"
	"fmt"
)

// SARIF 2.1.0 specification
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription SARIFText `json:"shortDescription"`
	FullDescription  SARIFText `json:"fullDescription,omitempty"`
	DefaultLevel     string    `json:"defaultConfiguration,omitempty"`
	HelpURI          string    `json:"helpUri,omitempty"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
	Kind      string          `json:"kind,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFText struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation  `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

type SARIFLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

// ConvertToSARIF converts StructuredReport to SARIF 2.1.0 format
func ConvertToSARIF(report *StructuredReport, hostname string) *SARIFReport {
	sarif := &SARIFReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []SARIFRun{},
	}

	// Build rules from issues
	rulesMap := make(map[string]SARIFRule)
	var results []SARIFResult

	for _, issue := range report.Issues {
		// Create rule if not exists
		if _, exists := rulesMap[issue.Code]; !exists {
			rulesMap[issue.Code] = SARIFRule{
				ID:   issue.Code,
				Name: issue.Code,
				ShortDescription: SARIFText{
					Text: issue.Msg,
				},
				FullDescription: SARIFText{
					Text: issue.Remediation,
				},
			}
		}

		// Map severity to SARIF level
		level := mapSeverityToSARIFLevel(issue.Severity)

		// Create result
		result := SARIFResult{
			RuleID: issue.Code,
			Level:  level,
			Message: SARIFMessage{
				Text: issue.Msg,
			},
			Kind: "fail",
		}

		// Try to map category to file location
		if location := mapCategoryToLocation(issue.Category, hostname); location != nil {
			result.Locations = []SARIFLocation{*location}
		}

		results = append(results, result)
	}

	// Build rules array
	var rules []SARIFRule
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	// Create run
	run := SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:           "chihuaudit",
				Version:        "1.0.0",
				InformationURI: "https://github.com/girste/chihuaudit",
				Rules:          rules,
			},
		},
		Results: results,
	}

	sarif.Runs = append(sarif.Runs, run)

	return sarif
}

func mapSeverityToSARIFLevel(severity string) string {
	switch severity {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	case "info":
		return "note"
	default:
		return "warning"
	}
}

func mapCategoryToLocation(category, hostname string) *SARIFLocation {
	// Map category to likely config file
	var uri string
	var logicalName string

	switch category {
	case "ssh":
		uri = "file:///etc/ssh/sshd_config"
		logicalName = "SSH Configuration"
	case "firewall":
		uri = "file:///etc/ufw/ufw.conf"
		logicalName = "Firewall Configuration"
	case "docker":
		uri = "file:///etc/docker/daemon.json"
		logicalName = "Docker Configuration"
	case "kernel":
		uri = "file:///etc/sysctl.conf"
		logicalName = "Kernel Configuration"
	case "updates":
		uri = "file:///etc/apt/sources.list"
		logicalName = "Package Sources"
	case "fail2ban":
		uri = "file:///etc/fail2ban/jail.conf"
		logicalName = "Fail2ban Configuration"
	case "mac":
		uri = "file:///etc/apparmor.d/"
		logicalName = "AppArmor Configuration"
	default:
		// Generic system location
		uri = fmt.Sprintf("system://%s", hostname)
		logicalName = fmt.Sprintf("%s subsystem", category)
	}

	return &SARIFLocation{
		PhysicalLocation: SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{
				URI: uri,
			},
		},
		LogicalLocations: []SARIFLogicalLocation{
			{
				Name: logicalName,
				Kind: "resource",
			},
		},
	}
}

// ToSARIFJSON outputs SARIF report as JSON
func (s *SARIFReport) ToJSON() (string, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
