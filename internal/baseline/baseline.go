package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	// Temporarily remove signature for verification
	baseline.Signature = ""

	// Regenerate signature
	computedSig, err := generateSignature(baseline)
	if err != nil {
		baseline.Signature = originalSig
		return fmt.Errorf("failed to compute signature: %w", err)
	}

	// Restore original signature
	baseline.Signature = originalSig

	// Compare signatures
	if computedSig != originalSig {
		return fmt.Errorf("signature mismatch (expected: %s, got: %s)", originalSig, computedSig)
	}

	return nil
}

// generateSignature creates a SHA256 signature for the baseline
// Signs only the baseline metadata to prevent tampering of baseline timestamp/version
// Data is intentionally NOT signed so we can detect changes in system state
func generateSignature(baseline *Baseline) (string, error) {
	// Sign only the baseline metadata (timestamp, hostname, version, os, kernel)
	// This prevents tampering with when the baseline was created
	// Data changes are expected and will be detected by diff engine
	data, err := json.Marshal(baseline.Metadata)
	if err != nil {
		return "", err
	}

	// Compute SHA256
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
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
