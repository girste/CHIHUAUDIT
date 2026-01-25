package monitoring

import (
	"testing"
)

func TestNewAnomalyDetector(t *testing.T) {
	d := NewAnomalyDetector()
	if d == nil {
		t.Fatal("NewAnomalyDetector returned nil")
	}

	if len(d.anomalies) != 0 {
		t.Errorf("anomalies should be empty, got %d", len(d.anomalies))
	}
}

func TestDetect_NilInputs(t *testing.T) {
	d := NewAnomalyDetector()

	// Both nil
	anomalies := d.Detect(nil, nil)
	if len(anomalies) != 0 {
		t.Errorf("Expected 0 anomalies for nil inputs, got %d", len(anomalies))
	}

	// Baseline nil
	anomalies = d.Detect(nil, map[string]interface{}{})
	if len(anomalies) != 0 {
		t.Errorf("Expected 0 anomalies for nil baseline, got %d", len(anomalies))
	}

	// Current nil
	anomalies = d.Detect(map[string]interface{}{}, nil)
	if len(anomalies) != 0 {
		t.Errorf("Expected 0 anomalies for nil current, got %d", len(anomalies))
	}
}

func TestDetect_FirewallDisabled(t *testing.T) {
	d := NewAnomalyDetector()

	baseline := map[string]interface{}{
		"firewall": map[string]interface{}{
			"active": true,
		},
	}

	current := map[string]interface{}{
		"firewall": map[string]interface{}{
			"active": false,
		},
	}

	anomalies := d.Detect(baseline, current)

	if len(anomalies) == 0 {
		t.Fatal("Expected anomaly for firewall disabled")
	}

	found := false
	for _, a := range anomalies {
		if a.Category == "firewall" && a.Severity == SeverityCritical {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected critical firewall anomaly")
	}
}

func TestDetect_NewOpenPorts(t *testing.T) {
	d := NewAnomalyDetector()

	baseline := map[string]interface{}{
		"firewall": map[string]interface{}{
			"active":    true,
			"openPorts": []interface{}{float64(22), float64(80)},
		},
	}

	current := map[string]interface{}{
		"firewall": map[string]interface{}{
			"active":    true,
			"openPorts": []interface{}{float64(22), float64(80), float64(3306), float64(5432)},
		},
	}

	anomalies := d.Detect(baseline, current)

	if len(anomalies) == 0 {
		t.Fatal("Expected anomaly for new open ports")
	}

	found := false
	for _, a := range anomalies {
		if a.Category == "firewall" && a.Severity == SeverityHigh {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected high severity anomaly for new ports")
	}
}

func TestDetect_SSHRootLoginEnabled(t *testing.T) {
	d := NewAnomalyDetector()

	baseline := map[string]interface{}{
		"ssh": map[string]interface{}{
			"permitRootLogin": "no",
		},
	}

	current := map[string]interface{}{
		"ssh": map[string]interface{}{
			"permitRootLogin": "yes",
		},
	}

	anomalies := d.Detect(baseline, current)

	if len(anomalies) == 0 {
		t.Fatal("Expected anomaly for root login enabled")
	}

	if !d.HasCritical() {
		t.Error("Should have critical anomaly")
	}
}

func TestDetect_Fail2banDisabled(t *testing.T) {
	d := NewAnomalyDetector()

	baseline := map[string]interface{}{
		"fail2ban": map[string]interface{}{
			"active": true,
		},
	}

	current := map[string]interface{}{
		"fail2ban": map[string]interface{}{
			"active": false,
		},
	}

	anomalies := d.Detect(baseline, current)

	if len(anomalies) == 0 {
		t.Fatal("Expected anomaly for fail2ban disabled")
	}

	if !d.HasHigh() {
		t.Error("Should have high severity anomaly")
	}
}

func TestDetect_AttackVolumeSpike(t *testing.T) {
	d := NewAnomalyDetector()

	baseline := map[string]interface{}{
		"threats": map[string]interface{}{
			"totalAttempts": float64(100),
		},
	}

	current := map[string]interface{}{
		"threats": map[string]interface{}{
			"totalAttempts": float64(500), // 5x increase
		},
	}

	anomalies := d.Detect(baseline, current)

	if len(anomalies) == 0 {
		t.Fatal("Expected anomaly for attack volume spike")
	}

	found := false
	for _, a := range anomalies {
		if a.Category == "threats" && a.Severity == SeverityHigh {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected high severity threat anomaly")
	}
}

func TestDetect_NewPrivilegedContainer(t *testing.T) {
	d := NewAnomalyDetector()

	baseline := map[string]interface{}{
		"docker": map[string]interface{}{
			"privilegedCount": float64(0),
		},
	}

	current := map[string]interface{}{
		"docker": map[string]interface{}{
			"privilegedCount": float64(2),
		},
	}

	anomalies := d.Detect(baseline, current)

	if len(anomalies) == 0 {
		t.Fatal("Expected anomaly for new privileged containers")
	}

	found := false
	for _, a := range anomalies {
		if a.Category == "docker" && a.Severity == SeverityHigh {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected high severity docker anomaly")
	}
}

func TestHasCritical(t *testing.T) {
	d := NewAnomalyDetector()

	// No anomalies
	if d.HasCritical() {
		t.Error("Should not have critical with no anomalies")
	}

	// Add non-critical
	d.addAnomaly(SeverityMedium, "test", "test", nil)
	if d.HasCritical() {
		t.Error("Should not have critical with only medium anomaly")
	}

	// Add critical
	d.addAnomaly(SeverityCritical, "test", "test", nil)
	if !d.HasCritical() {
		t.Error("Should have critical")
	}
}

func TestHasHigh(t *testing.T) {
	d := NewAnomalyDetector()

	// No anomalies
	if d.HasHigh() {
		t.Error("Should not have high with no anomalies")
	}

	// Add low severity
	d.addAnomaly(SeverityLow, "test", "test", nil)
	if d.HasHigh() {
		t.Error("Should not have high with only low anomaly")
	}

	// Add high
	d.addAnomaly(SeverityHigh, "test", "test", nil)
	if !d.HasHigh() {
		t.Error("Should have high")
	}

	// Critical also counts as high
	d2 := NewAnomalyDetector()
	d2.addAnomaly(SeverityCritical, "test", "test", nil)
	if !d2.HasHigh() {
		t.Error("Critical should count as high")
	}
}

func TestHelperFunctions(t *testing.T) {
	// Test getMap
	m := map[string]interface{}{
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	nested := getMap(m, "nested")
	if nested == nil {
		t.Error("getMap should return nested map")
	}

	missing := getMap(m, "missing")
	if missing != nil {
		t.Error("getMap should return nil for missing key")
	}

	// Test getString
	m2 := map[string]interface{}{
		"str": "value",
	}
	if getString(m2, "str") != "value" {
		t.Error("getString should return string value")
	}
	if getString(m2, "missing") != "" {
		t.Error("getString should return empty for missing key")
	}

	// Test getInt
	m3 := map[string]interface{}{
		"int":     42,
		"float64": float64(123),
	}
	if getInt(m3, "int") != 42 {
		t.Error("getInt should return int value")
	}
	if getInt(m3, "float64") != 123 {
		t.Error("getInt should handle float64")
	}
	if getInt(m3, "missing") != 0 {
		t.Error("getInt should return 0 for missing key")
	}

	// Test getIntSlice
	m4 := map[string]interface{}{
		"slice": []interface{}{float64(1), float64(2), float64(3)},
	}
	slice := getIntSlice(m4, "slice")
	if len(slice) != 3 {
		t.Errorf("getIntSlice should return 3 items, got %d", len(slice))
	}

	// Test diffIntSlice
	current := []int{1, 2, 3, 4, 5}
	baseline := []int{1, 2, 3}
	diff := diffIntSlice(current, baseline)
	if len(diff) != 2 {
		t.Errorf("diffIntSlice should return 2 items, got %d", len(diff))
	}
}

func TestDetect_NoChanges(t *testing.T) {
	d := NewAnomalyDetector()

	state := map[string]interface{}{
		"firewall": map[string]interface{}{
			"active":    true,
			"openPorts": []interface{}{float64(22), float64(80)},
		},
		"ssh": map[string]interface{}{
			"permitRootLogin": "no",
		},
		"fail2ban": map[string]interface{}{
			"active": true,
		},
	}

	// Same state for baseline and current
	anomalies := d.Detect(state, state)

	if len(anomalies) != 0 {
		t.Errorf("Expected 0 anomalies for unchanged state, got %d", len(anomalies))
	}
}
