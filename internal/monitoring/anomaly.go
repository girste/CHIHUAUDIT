package monitoring

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/girste/chihuaudit/internal/config"
)

// Severity levels
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Anomaly represents a detected security change
type Anomaly struct {
	Severity string                 `json:"severity"`
	Category string                 `json:"category"`
	Message  string                 `json:"message"`
	Details  map[string]interface{} `json:"details,omitempty"`
}

// AnomalyDetector compares baseline and current state
type AnomalyDetector struct {
	anomalies []Anomaly
}

// NewAnomalyDetector creates a new detector
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		anomalies: []Anomaly{},
	}
}

// Detect compares baseline vs current and returns anomalies
func (d *AnomalyDetector) Detect(baseline, current map[string]interface{}) []Anomaly {
	d.anomalies = []Anomaly{}

	if baseline == nil || current == nil {
		return d.anomalies
	}

	d.checkFirewall(getMap(baseline, "firewall"), getMap(current, "firewall"))
	d.checkSSH(getMap(baseline, "ssh"), getMap(current, "ssh"))
	d.checkServices(getMap(baseline, "services"), getMap(current, "services"))
	d.checkFail2ban(getMap(baseline, "fail2ban"), getMap(current, "fail2ban"))
	d.checkThreats(getMap(baseline, "threats"), getMap(current, "threats"))
	d.checkDocker(getMap(baseline, "docker"), getMap(current, "docker"))
	d.checkUpdates(getMap(baseline, "updates"), getMap(current, "updates"))

	return d.anomalies
}

// HasCritical returns true if any critical anomalies were detected
func (d *AnomalyDetector) HasCritical() bool {
	for _, a := range d.anomalies {
		if a.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// HasHigh returns true if any high or critical anomalies were detected
func (d *AnomalyDetector) HasHigh() bool {
	for _, a := range d.anomalies {
		if a.Severity == SeverityCritical || a.Severity == SeverityHigh {
			return true
		}
	}
	return false
}

func (d *AnomalyDetector) addAnomaly(severity, category, message string, details map[string]interface{}) {
	d.anomalies = append(d.anomalies, Anomaly{
		Severity: severity,
		Category: category,
		Message:  message,
		Details:  details,
	})
}

func (d *AnomalyDetector) checkFirewall(baseline, current map[string]interface{}) {
	if baseline == nil || current == nil {
		return
	}

	// Firewall disabled
	baselineActive, _ := baseline["active"].(bool)
	currentActive, _ := current["active"].(bool)
	if baselineActive && !currentActive {
		d.addAnomaly(SeverityCritical, "firewall", "Firewall was disabled", nil)
	}

	// New open ports
	baselinePorts := getIntSlice(baseline, "openPorts")
	currentPorts := getIntSlice(current, "openPorts")
	newPorts := diffIntSlice(currentPorts, baselinePorts)

	if len(newPorts) > 0 {
		sort.Ints(newPorts)
		d.addAnomaly(SeverityHigh, "firewall",
			fmt.Sprintf("New ports opened: %v", newPorts),
			map[string]interface{}{"ports": newPorts})
	}

	// Rules count changed significantly
	baselineRules := getInt(baseline, "rulesCount")
	currentRules := getInt(current, "rulesCount")
	diff := currentRules - baselineRules
	if diff < 0 {
		diff = -diff
	}
	if diff > 5 {
		d.addAnomaly(SeverityMedium, "firewall",
			fmt.Sprintf("Firewall rules changed: %d -> %d", baselineRules, currentRules), nil)
	}
}

func (d *AnomalyDetector) checkSSH(baseline, current map[string]interface{}) {
	if baseline == nil || current == nil {
		return
	}

	// Port changed
	baselinePort := getString(baseline, "port")
	currentPort := getString(current, "port")
	if baselinePort != currentPort {
		d.addAnomaly(SeverityMedium, "ssh",
			fmt.Sprintf("SSH port changed: %s -> %s", baselinePort, currentPort), nil)
	}

	// Root login enabled
	baselineRoot := getString(baseline, "permitRootLogin")
	currentRoot := getString(current, "permitRootLogin")
	if baselineRoot == "no" && currentRoot != "no" {
		d.addAnomaly(SeverityCritical, "ssh", "Root login was enabled in SSH config", nil)
	}

	// Password auth enabled
	baselinePwd := getString(baseline, "passwordAuth")
	currentPwd := getString(current, "passwordAuth")
	if baselinePwd == "no" && currentPwd == "yes" {
		d.addAnomaly(SeverityHigh, "ssh", "Password authentication was enabled in SSH", nil)
	}
}

func (d *AnomalyDetector) checkServices(baseline, current map[string]interface{}) {
	if baseline == nil || current == nil {
		return
	}

	// New listening ports
	baselinePorts := getIntSlice(baseline, "listeningPorts")
	currentPorts := getIntSlice(current, "listeningPorts")
	newPorts := diffIntSlice(currentPorts, baselinePorts)

	if len(newPorts) > 0 {
		sort.Ints(newPorts)

		// Enrich port details with process information
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		enriched := EnrichPortDetails(ctx, newPorts)

		// Filter out whitelisted processes
		whitelist, _ := config.LoadWhitelist()
		var suspicious []PortDetail
		for _, detail := range enriched {
			// Check if process is whitelisted based on name and bind address
			if whitelist != nil && whitelist.IsProcessAllowed(detail.Process, detail.Bind) {
				continue // Skip whitelisted process
			}
			suspicious = append(suspicious, detail)
		}

		// Only add anomaly if there are non-whitelisted ports
		if len(suspicious) > 0 {
			d.addAnomaly(SeverityMedium, "services",
				FormatEnrichedMessage(suspicious),
				map[string]interface{}{
					"ports":    newPorts,
					"enriched": suspicious,
				})
		}
	}

	// Large increase in exposed services
	baselineCount := getInt(baseline, "exposedCount")
	currentCount := getInt(current, "exposedCount")
	if currentCount > baselineCount+3 {
		d.addAnomaly(SeverityMedium, "services",
			fmt.Sprintf("Exposed services increased: %d -> %d", baselineCount, currentCount), nil)
	}
}

func (d *AnomalyDetector) checkFail2ban(baseline, current map[string]interface{}) {
	if baseline == nil || current == nil {
		return
	}

	baselineActive, _ := baseline["active"].(bool)
	currentActive, _ := current["active"].(bool)
	if baselineActive && !currentActive {
		d.addAnomaly(SeverityHigh, "fail2ban", "Fail2ban was disabled or stopped", nil)
	}
}

func (d *AnomalyDetector) checkThreats(baseline, current map[string]interface{}) {
	if baseline == nil || current == nil {
		return
	}

	baselineAttempts := getInt(baseline, "totalAttempts")
	currentAttempts := getInt(current, "totalAttempts")

	// Significant increase (>200%)
	if baselineAttempts > 0 && currentAttempts > baselineAttempts*3 {
		d.addAnomaly(SeverityHigh, "threats",
			fmt.Sprintf("Attack volume spike: %d -> %d attempts", baselineAttempts, currentAttempts),
			map[string]interface{}{"baseline": baselineAttempts, "current": currentAttempts})
	}

	// New unique IPs (>50% increase)
	baselineIPs := getInt(baseline, "uniqueIPs")
	currentIPs := getInt(current, "uniqueIPs")
	if baselineIPs > 0 && currentIPs > baselineIPs*3/2 {
		d.addAnomaly(SeverityMedium, "threats",
			fmt.Sprintf("New attacker IPs detected: %d -> %d", baselineIPs, currentIPs), nil)
	}
}

func (d *AnomalyDetector) checkDocker(baseline, current map[string]interface{}) {
	if baseline == nil || current == nil {
		return
	}

	// New privileged containers
	baselinePriv := getInt(baseline, "privilegedCount")
	currentPriv := getInt(current, "privilegedCount")
	if currentPriv > baselinePriv {
		d.addAnomaly(SeverityHigh, "docker",
			fmt.Sprintf("New privileged container(s) detected: %d", currentPriv-baselinePriv), nil)
	}

	// Container count spike
	baselineContainers := getInt(baseline, "runningContainers")
	currentContainers := getInt(current, "runningContainers")
	if currentContainers > baselineContainers+5 {
		d.addAnomaly(SeverityLow, "docker",
			fmt.Sprintf("Many new containers started: %d -> %d", baselineContainers, currentContainers), nil)
	}
}

func (d *AnomalyDetector) checkUpdates(baseline, current map[string]interface{}) {
	if baseline == nil || current == nil {
		return
	}

	baselineUpdates := getInt(baseline, "securityUpdates")
	currentUpdates := getInt(current, "securityUpdates")

	if currentUpdates > 10 && currentUpdates > baselineUpdates {
		d.addAnomaly(SeverityHigh, "updates",
			fmt.Sprintf("%d critical security updates now available", currentUpdates), nil)
	}
}

// Helper functions
func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	}
	return 0
}

func getIntSlice(m map[string]interface{}, key string) []int {
	result := []int{}
	switch v := m[key].(type) {
	case []int:
		return v
	case []interface{}:
		for _, item := range v {
			switch n := item.(type) {
			case int:
				result = append(result, n)
			case float64:
				result = append(result, int(n))
			}
		}
	}
	return result
}

func diffIntSlice(current, baseline []int) []int {
	baselineSet := make(map[int]bool)
	for _, v := range baseline {
		baselineSet[v] = true
	}

	var diff []int
	for _, v := range current {
		if !baselineSet[v] {
			diff = append(diff, v)
		}
	}
	return diff
}
