package monitoring

import (
	"fmt"
	"strings"
	"time"
)

// BulletinGenerator creates human-readable security bulletins
type BulletinGenerator struct{}

// NewBulletinGenerator creates a new generator
func NewBulletinGenerator() *BulletinGenerator {
	return &BulletinGenerator{}
}

// Generate creates a security bulletin
func (g *BulletinGenerator) Generate(report map[string]interface{}, anomalies []Anomaly, baselineAgeHours float64) string {
	var lines []string
	timestamp := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")

	// Header
	lines = append(lines, strings.Repeat("=", 70))
	lines = append(lines, "CHIHUAUDIT - Security Bulletin")
	lines = append(lines, fmt.Sprintf("Generated: %s", timestamp))
	lines = append(lines, strings.Repeat("=", 70))
	lines = append(lines, "")

	// Overall status
	status := g.getStatus(report, anomalies)
	lines = append(lines, fmt.Sprintf("Status: %s", status))

	if baselineAgeHours > 0 {
		lines = append(lines, fmt.Sprintf("Monitoring since: %.1f hours ago", baselineAgeHours))
	}
	lines = append(lines, "")

	// Anomalies section
	if len(anomalies) > 0 {
		lines = append(lines, "ANOMALIES DETECTED:")
		lines = append(lines, strings.Repeat("-", 70))

		// Group by severity
		critical := filterBySeverity(anomalies, SeverityCritical)
		high := filterBySeverity(anomalies, SeverityHigh)
		medium := filterBySeverity(anomalies, SeverityMedium)
		low := filterBySeverity(anomalies, SeverityLow)

		if len(critical) > 0 {
			lines = append(lines, "\n[CRITICAL]")
			for _, a := range critical {
				lines = append(lines, fmt.Sprintf("  ! %s: %s", strings.ToUpper(a.Category), a.Message))
			}
		}

		if len(high) > 0 {
			lines = append(lines, "\n[HIGH]")
			for _, a := range high {
				lines = append(lines, fmt.Sprintf("  * %s: %s", strings.ToUpper(a.Category), a.Message))
			}
		}

		if len(medium) > 0 {
			lines = append(lines, "\n[MEDIUM]")
			for _, a := range medium {
				lines = append(lines, fmt.Sprintf("  - %s: %s", a.Category, a.Message))
			}
		}

		if len(low) > 0 {
			lines = append(lines, "\n[LOW]")
			for _, a := range low {
				lines = append(lines, fmt.Sprintf("  . %s: %s", a.Category, a.Message))
			}
		}
		lines = append(lines, "")
	} else {
		lines = append(lines, "No anomalies detected - all systems nominal")
		lines = append(lines, "")
	}

	// Quick stats
	lines = append(lines, "CURRENT STATE:")
	lines = append(lines, strings.Repeat("-", 70))

	// Analysis summary
	if analysis, ok := report["analysis"].(map[string]interface{}); ok {
		if status, ok := analysis["overallStatus"].(string); ok {
			lines = append(lines, fmt.Sprintf("Overall: %s", status))
		}
		if score, ok := analysis["score"].(map[string]int); ok {
			lines = append(lines, fmt.Sprintf("Issues: %d critical, %d high priority",
				score["criticalIssues"], score["highPriorityIssues"]))
		}
	}

	// Firewall
	if fw, ok := report["firewall"].(map[string]interface{}); ok {
		active := "INACTIVE"
		if a, ok := fw["active"].(bool); ok && a {
			active = "ACTIVE"
		}
		fwType := "unknown"
		if t, ok := fw["type"].(string); ok {
			fwType = t
		}
		rulesCount := 0
		if r, ok := fw["rulesCount"].(int); ok {
			rulesCount = r
		}
		openPorts := 0
		if p, ok := fw["openPorts"].([]int); ok {
			openPorts = len(p)
		}
		lines = append(lines, fmt.Sprintf("Firewall: %s (%s) - %d rules, %d open ports",
			active, fwType, rulesCount, openPorts))
	}

	// SSH
	if ssh, ok := report["ssh"].(map[string]interface{}); ok {
		port := ssh["port"]
		rootLogin := ssh["permitRootLogin"]
		pwdAuth := ssh["passwordAuth"]
		lines = append(lines, fmt.Sprintf("SSH: Port %v - Root=%v, Password=%v", port, rootLogin, pwdAuth))
	}

	// Threats
	if threats, ok := report["threats"].(map[string]interface{}); ok {
		totalAttempts := getInt(threats, "totalAttempts")
		uniqueIPs := getInt(threats, "uniqueIPs")
		days := getInt(threats, "periodDays")
		if days == 0 {
			days = 7
		}
		lines = append(lines, fmt.Sprintf("Threats: %d failed login attempts from %d IPs (%d days)",
			totalAttempts, uniqueIPs, days))
	}

	// Fail2ban
	if f2b, ok := report["fail2ban"].(map[string]interface{}); ok {
		if active, ok := f2b["active"].(bool); ok && active {
			banned := getInt(f2b, "totalBanned")
			lines = append(lines, fmt.Sprintf("Fail2ban: ACTIVE - %d IPs banned", banned))
		} else {
			lines = append(lines, "Fail2ban: INACTIVE")
		}
	}

	// Docker
	if docker, ok := report["docker"].(map[string]interface{}); ok {
		if installed, ok := docker["installed"].(bool); ok && installed {
			containers := getInt(docker, "runningContainers")
			lines = append(lines, fmt.Sprintf("Docker: %d containers running", containers))
		}
	}

	lines = append(lines, "")
	lines = append(lines, strings.Repeat("=", 70))

	return strings.Join(lines, "\n")
}

func (g *BulletinGenerator) getStatus(report map[string]interface{}, anomalies []Anomaly) string {
	if len(anomalies) == 0 {
		if analysis, ok := report["analysis"].(map[string]interface{}); ok {
			if status, ok := analysis["overallStatus"].(string); ok {
				switch status {
				case "good":
					return "OK - ALL OK"
				case "fair":
					return "OK (minor warnings)"
				default:
					return fmt.Sprintf("WARNING - %s", status)
				}
			}
		}
		return "OK"
	}

	// Has anomalies
	hasCritical := false
	hasHigh := false
	for _, a := range anomalies {
		if a.Severity == SeverityCritical {
			hasCritical = true
		}
		if a.Severity == SeverityHigh {
			hasHigh = true
		}
	}

	if hasCritical {
		return "CRITICAL ANOMALY DETECTED"
	}
	if hasHigh {
		return "HIGH SEVERITY ANOMALY DETECTED"
	}
	return "ANOMALIES DETECTED"
}

func filterBySeverity(anomalies []Anomaly, severity string) []Anomaly {
	var result []Anomaly
	for _, a := range anomalies {
		if a.Severity == severity {
			result = append(result, a)
		}
	}
	return result
}
