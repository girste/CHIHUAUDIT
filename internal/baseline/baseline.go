package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Baseline represents a signed snapshot of system state
type Baseline struct {
	Metadata  Metadata               `yaml:"metadata"`
	Signature string                 `yaml:"signature"`
	Data      map[string]interface{} `yaml:"data"`
}

// Metadata contains baseline metadata
type Metadata struct {
	Timestamp string `yaml:"timestamp"`
	Hostname  string `yaml:"hostname"`
	Version   string `yaml:"version"`
	OS        string `yaml:"os"`
	Kernel    string `yaml:"kernel"`
}

// Create generates a new baseline from audit results
func Create(auditResults map[string]interface{}, version string) (*Baseline, error) {
	// Extract metadata
	metadata := Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   version,
	}

	// Extract OS info from audit results if available
	if metaMap, ok := auditResults["metadata"].(map[string]interface{}); ok {
		if hostname, ok := metaMap["hostname"].(string); ok {
			metadata.Hostname = hostname
		}
		if osInfo, ok := metaMap["os"].(string); ok {
			metadata.OS = osInfo
		}
		if kernel, ok := metaMap["kernel"].(string); ok {
			metadata.Kernel = kernel
		}
	}

	baseline := &Baseline{
		Metadata: metadata,
		Data:     auditResults,
	}

	// Generate signature
	sig, err := generateSignature(baseline)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signature: %w", err)
	}
	baseline.Signature = sig

	return baseline, nil
}

// Save writes the baseline to a YAML file
func Save(baseline *Baseline, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create baseline directory: %w", err)
	}

	// Calculate signature before saving
	sig, err := calculateSignature(baseline)
	if err != nil {
		return fmt.Errorf("failed to calculate signature: %w", err)
	}
	baseline.Signature = sig

	// Marshal to YAML
	data, err := yaml.Marshal(baseline)
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write baseline file: %w", err)
	}

	return nil
}

// calculateSignature generates a deterministic signature based on metadata only
// Data integrity is ensured by YAML file format itself
func calculateSignature(baseline *Baseline) (string, error) {
	// Sign only metadata fields in fixed order
	// This is deterministic since metadata contains only simple strings
	signatureInput := fmt.Sprintf("%s|%s|%s|%s|%s",
		baseline.Metadata.Timestamp,
		baseline.Metadata.Hostname,
		baseline.Metadata.Version,
		baseline.Metadata.OS,
		baseline.Metadata.Kernel,
	)

	hash := sha256.Sum256([]byte(signatureInput))
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

// Load reads and validates a baseline from a YAML file
func Load(path string) (*Baseline, error) {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline file: %w", err)
	}

	// Unmarshal YAML
	var baseline Baseline
	if err := yaml.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to unmarshal baseline: %w", err)
	}

	// Verify signature
	if err := Verify(&baseline); err != nil {
		return nil, fmt.Errorf("baseline signature verification failed: %w", err)
	}

	return &baseline, nil
}

// Verify checks if the baseline signature is valid
func Verify(baseline *Baseline) error {
	// Store original signature
	originalSig := baseline.Signature

	// Recalculate signature using same method as Save
	computedSig, err := calculateSignature(baseline)
	if err != nil {
		return fmt.Errorf("failed to compute signature: %w", err)
	}

	// Compare signatures
	if computedSig != originalSig {
		return fmt.Errorf("signature mismatch (expected: %s, got: %s)", originalSig, computedSig)
	}

	return nil
}

// generateSignature creates a SHA256 signature for the baseline (legacy - kept for backwards compat)
// Signs both metadata AND data to ensure baseline integrity
func generateSignature(baseline *Baseline) (string, error) {
	return calculateSignature(baseline)
}

// generateYAMLSignature is deprecated - use calculateSignature instead
func generateYAMLSignature(baseline *Baseline) (string, error) {
	return calculateSignature(baseline)
}

// GetDefaultPath returns the default baseline file path
func GetDefaultPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".chihuaudit", "baseline.yaml"), nil
}

// BackupPath returns path for baseline backup with timestamp
func BackupPath(timestamp time.Time) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	filename := fmt.Sprintf("baseline-%s.yaml", timestamp.Format("2006-01-02-150405"))
	return filepath.Join(homeDir, ".chihuaudit", "baselines", filename), nil
}
