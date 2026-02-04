package baseline

import (
	"path/filepath"
	"testing"
)

func TestCreateBaseline(t *testing.T) {
	auditResults := map[string]interface{}{
		"metadata": map[string]interface{}{
			"hostname": "test-host",
			"os":       "linux",
			"kernel":   "5.10.0",
		},
		"firewall": map[string]interface{}{
			"active": true,
			"rules":  []interface{}{"allow 22/tcp", "allow 80/tcp"},
		},
	}

	bl, err := Create(auditResults, "1.0.0")
	if err != nil {
		t.Fatalf("Failed to create baseline: %v", err)
	}

	if bl.Metadata.Hostname != "test-host" {
		t.Errorf("Expected hostname 'test-host', got '%s'", bl.Metadata.Hostname)
	}

	if bl.Metadata.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", bl.Metadata.Version)
	}

	if bl.Signature == "" {
		t.Error("Signature should not be empty")
	}
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.yaml")

	auditResults := map[string]interface{}{
		"metadata": map[string]interface{}{
			"hostname": "test-host",
		},
		"firewall": map[string]interface{}{
			"active": true,
		},
	}

	// Create and save
	bl, err := Create(auditResults, "1.0.0")
	if err != nil {
		t.Fatalf("Failed to create baseline: %v", err)
	}

	if err := Save(bl, baselinePath); err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	// Load and verify
	loaded, err := Load(baselinePath)
	if err != nil {
		t.Fatalf("Failed to load baseline: %v", err)
	}

	if loaded.Metadata.Hostname != bl.Metadata.Hostname {
		t.Errorf("Loaded hostname mismatch")
	}

	if loaded.Signature != bl.Signature {
		t.Errorf("Loaded signature mismatch")
	}
}

func TestSignatureVerification(t *testing.T) {
	auditResults := map[string]interface{}{
		"firewall": map[string]interface{}{
			"active": true,
		},
	}

	bl, err := Create(auditResults, "1.0.0")
	if err != nil {
		t.Fatalf("Failed to create baseline: %v", err)
	}

	// Verify should pass
	if err := Verify(bl); err != nil {
		t.Errorf("Verification should pass: %v", err)
	}

	// Tamper with signature
	bl.Signature = "sha256:invalid"
	if err := Verify(bl); err == nil {
		t.Error("Verification should fail for invalid signature")
	}
}

func TestSignatureStability(t *testing.T) {
	// Same metadata should produce same signature
	metadata := Metadata{
		Timestamp: "2026-02-03T00:00:00Z",
		Hostname:  "test-host",
		Version:   "1.0.0",
	}

	bl1 := &Baseline{Metadata: metadata}
	sig1, err1 := generateSignature(bl1)

	bl2 := &Baseline{Metadata: metadata}
	sig2, err2 := generateSignature(bl2)

	if err1 != nil || err2 != nil {
		t.Fatal("Failed to generate signatures")
	}

	if sig1 != sig2 {
		t.Error("Same metadata should produce same signature")
	}
}

func TestCompare_NoDrift(t *testing.T) {
	auditResults := map[string]interface{}{
		"metadata": map[string]interface{}{
			"hostname":  "test-host",
			"timestamp": "2026-02-03T10:00:00Z",
		},
		"firewall": map[string]interface{}{
			"active": true,
			"rules":  []interface{}{"allow 22/tcp"},
		},
	}

	baseline, err := Create(auditResults, "1.0.0")
	if err != nil {
		t.Fatalf("Failed to create baseline: %v", err)
	}

	diffResult, err := Compare(baseline, auditResults)
	if err != nil {
		t.Fatalf("Failed to compare: %v", err)
	}

	if diffResult.DriftCount != 0 {
		t.Errorf("Expected 0 drifts, got %d", diffResult.DriftCount)
	}
}

func TestCompare_WithDrift(t *testing.T) {
	baselineData := map[string]interface{}{
		"metadata": map[string]interface{}{
			"hostname":  "test-host",
			"timestamp": "2026-02-03T10:00:00Z",
		},
		"firewall": map[string]interface{}{
			"active": true,
			"rules":  []interface{}{"allow 22/tcp"},
		},
	}

	baseline, err := Create(baselineData, "1.0.0")
	if err != nil {
		t.Fatalf("Failed to create baseline: %v", err)
	}

	currentData := map[string]interface{}{
		"metadata": map[string]interface{}{
			"hostname":  "test-host",
			"timestamp": "2026-02-03T11:00:00Z",
		},
		"firewall": map[string]interface{}{
			"active": true,
			"rules":  []interface{}{"allow 22/tcp", "allow 80/tcp"},
		},
	}

	diffResult, err := Compare(baseline, currentData)
	if err != nil {
		t.Fatalf("Failed to compare: %v", err)
	}

	if diffResult.DriftCount == 0 {
		t.Error("Expected drifts to be detected")
	}
}

func TestDeepEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        interface{}
		b        interface{}
		expected bool
	}{
		{"both nil", nil, nil, true},
		{"one nil", nil, "test", false},
		{"same strings", "test", "test", true},
		{"different strings", "test", "other", false},
		{"empty slices", []interface{}{}, []interface{}{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deepEqual(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("deepEqual() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestLoadNonExistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path/baseline.yaml")
	if err == nil {
		t.Error("Expected error loading non-existent file")
	}
}

func TestGetDefaultPath(t *testing.T) {
}
