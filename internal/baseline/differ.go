package baseline

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// ChangeType represents the type of change detected
type ChangeType string

const (
	ChangeTypeAdded    ChangeType = "added"
	ChangeTypeRemoved  ChangeType = "removed"
	ChangeTypeModified ChangeType = "modified"
)

// Drift represents a single configuration drift
type Drift struct {
	Analyzer   string      `json:"analyzer" yaml:"analyzer"`
	ChangeType ChangeType  `json:"change_type" yaml:"change_type"`
	Field      string      `json:"field" yaml:"field"`
	Before     interface{} `json:"before,omitempty" yaml:"before,omitempty"`
	After      interface{} `json:"after,omitempty" yaml:"after,omitempty"`
	Message    string      `json:"message" yaml:"message"`
}

// DiffResult contains all detected drifts
type DiffResult struct {
	BaselineTimestamp string  `json:"baseline_timestamp" yaml:"baseline_timestamp"`
	CurrentTimestamp  string  `json:"current_timestamp" yaml:"current_timestamp"`
	DriftCount        int     `json:"drift_count" yaml:"drift_count"`
	Drifts            []Drift `json:"drifts" yaml:"drifts"`
}

// Compare compares baseline against current audit results and returns drifts
func Compare(baseline *Baseline, currentResults map[string]interface{}) (*DiffResult, error) {
	result := &DiffResult{
		BaselineTimestamp: baseline.Metadata.Timestamp,
		Drifts:            []Drift{},
	}

	// Extract current timestamp
	if metaMap, ok := currentResults["metadata"].(map[string]interface{}); ok {
		if ts, ok := metaMap["timestamp"].(string); ok {
			result.CurrentTimestamp = ts
		}
	}

	// Compare each analyzer's data
	for analyzerName, baselineData := range baseline.Data {
		// Skip metadata and meta-analyzers
		if analyzerName == "metadata" || analyzerName == "timestamp" ||
			analyzerName == "os" || analyzerName == "kernel" || analyzerName == "hostname" ||
			analyzerName == "recommendations" {
			continue
		}

		currentData, exists := currentResults[analyzerName]
		if !exists {
			// Analyzer no longer running
			result.Drifts = append(result.Drifts, Drift{
				Analyzer:   analyzerName,
				ChangeType: ChangeTypeRemoved,
				Field:      "analyzer",
				Before:     baselineData,
				After:      nil,
				Message:    fmt.Sprintf("Analyzer %s no longer present", analyzerName),
			})
			continue
		}

		// Compare analyzer data
		drifts := compareAnalyzerData(analyzerName, baselineData, currentData)
		result.Drifts = append(result.Drifts, drifts...)
	}

	// Check for new analyzers
	for analyzerName, currentData := range currentResults {
		// Skip metadata and meta-analyzers
		if analyzerName == "metadata" || analyzerName == "timestamp" ||
			analyzerName == "os" || analyzerName == "kernel" || analyzerName == "hostname" ||
			analyzerName == "recommendations" {
			continue
		}

		if _, exists := baseline.Data[analyzerName]; !exists {
			result.Drifts = append(result.Drifts, Drift{
				Analyzer:   analyzerName,
				ChangeType: ChangeTypeAdded,
				Field:      "analyzer",
				Before:     nil,
				After:      currentData,
				Message:    fmt.Sprintf("New analyzer %s detected", analyzerName),
			})
		}
	}

	result.DriftCount = len(result.Drifts)
	return result, nil
}

// compareAnalyzerData compares data from a specific analyzer
func compareAnalyzerData(analyzerName string, baseline, current interface{}) []Drift {
	drifts := []Drift{}

	baselineMap, baselineIsMap := baseline.(map[string]interface{})
	currentMap, currentIsMap := current.(map[string]interface{})

	if !baselineIsMap || !currentIsMap {
		// Can't compare non-map data, treat as modified if different
		if !reflect.DeepEqual(baseline, current) {
			drifts = append(drifts, Drift{
				Analyzer:   analyzerName,
				ChangeType: ChangeTypeModified,
				Field:      "data",
				Before:     baseline,
				After:      current,
				Message:    fmt.Sprintf("%s data changed", analyzerName),
			})
		}
		return drifts
	}

	// Skip meta-analyzers that don't represent system state
	if analyzerName == "analysis" || analyzerName == "recommendations" {
		return drifts
	}

	// Compare maps field by field
	allKeys := make(map[string]bool)
	for k := range baselineMap {
		allKeys[k] = true
	}
	for k := range currentMap {
		allKeys[k] = true
	}

	for key := range allKeys {
		baselineVal, baselineExists := baselineMap[key]
		currentVal, currentExists := currentMap[key]

		if !baselineExists && currentExists {
			// New field added
			drifts = append(drifts, Drift{
				Analyzer:   analyzerName,
				ChangeType: ChangeTypeAdded,
				Field:      key,
				Before:     nil,
				After:      currentVal,
				Message:    fmt.Sprintf("%s: %s added", analyzerName, key),
			})
		} else if baselineExists && !currentExists {
			// Field removed
			drifts = append(drifts, Drift{
				Analyzer:   analyzerName,
				ChangeType: ChangeTypeRemoved,
				Field:      key,
				Before:     baselineVal,
				After:      nil,
				Message:    fmt.Sprintf("%s: %s removed", analyzerName, key),
			})
		} else if !deepEqual(baselineVal, currentVal) {
			// Field modified - only report if actually different
			drifts = append(drifts, Drift{
				Analyzer:   analyzerName,
				ChangeType: ChangeTypeModified,
				Field:      key,
				Before:     baselineVal,
				After:      currentVal,
				Message:    fmt.Sprintf("%s: %s changed", analyzerName, key),
			})
		}
	}

	return drifts
}

// deepEqual compares two values for equality, handling edge cases
func deepEqual(a, b interface{}) bool {
	// Handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Handle empty slices/maps
	aSlice, aIsSlice := a.([]interface{})
	bSlice, bIsSlice := b.([]interface{})
	if aIsSlice && bIsSlice {
		if len(aSlice) == 0 && len(bSlice) == 0 {
			return true
		}
	}

	// For complex types, compare JSON representation
	// This handles cases where reflect.DeepEqual fails due to type differences
	aJSON, aErr := json.Marshal(a)
	bJSON, bErr := json.Marshal(b)
	if aErr == nil && bErr == nil {
		return string(aJSON) == string(bJSON)
	}

	// Fallback to reflect.DeepEqual
	return reflect.DeepEqual(a, b)
}
