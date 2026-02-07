package alerting

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// CompareGeneric performs a deep diff between two JSON audit results
// Returns all changes except those in ignore list from config
func CompareGeneric(prevRaw, currRaw json.RawMessage, cfg *Config) []Change {
	if prevRaw == nil || len(prevRaw) == 0 {
		return nil
	}

	var prev, curr map[string]any
	if err := json.Unmarshal(prevRaw, &prev); err != nil {
		return nil
	}
	if err := json.Unmarshal(currRaw, &curr); err != nil {
		return nil
	}

	// Build ignore map from config ONLY (no defaults in backend)
	ignoreMap := make(map[string]bool)
	if cfg != nil {
		for _, k := range cfg.IgnoreChanges {
			ignoreMap[k] = true
		}
	}

	var changes []Change
	deepDiff("", prev, curr, ignoreMap, &changes)
	return changes
}

// deepDiff recursively compares two values and detects changes
func deepDiff(path string, prev, curr any, ignore map[string]bool, changes *[]Change) {
	// Skip if this path is ignored (exact match OR prefix match)
	if shouldIgnorePath(path, ignore) {
		return
	}

	// Handle nil cases
	if prev == nil && curr == nil {
		return
	}
	if prev == nil && curr != nil {
		// New value appeared
		*changes = append(*changes, Change{
			Key:         path,
			Description: fmt.Sprintf("%s: added", formatPath(path)),
			OldValue:    nil,
			NewValue:    curr,
		})
		return
	}
	if prev != nil && curr == nil {
		// Value disappeared
		*changes = append(*changes, Change{
			Key:         path,
			Description: fmt.Sprintf("%s: removed", formatPath(path)),
			OldValue:    prev,
			NewValue:    nil,
		})
		return
	}

	// Compare based on type
	switch prevVal := prev.(type) {
	case map[string]any:
		currMap, ok := curr.(map[string]any)
		if !ok {
			// Type changed
			*changes = append(*changes, Change{
				Key:         path,
				Description: fmt.Sprintf("%s: type changed", formatPath(path)),
				OldValue:    prev,
				NewValue:    curr,
			})
			return
		}

		// Check all keys in both maps
		allKeys := make(map[string]bool)
		for k := range prevVal {
			allKeys[k] = true
		}
		for k := range currMap {
			allKeys[k] = true
		}

		for k := range allKeys {
			newPath := path
			if newPath == "" {
				newPath = k
			} else {
				newPath = path + "." + k
			}
			deepDiff(newPath, prevVal[k], currMap[k], ignore, changes)
		}

	case []any:
		currArr, ok := curr.([]any)
		if !ok {
			// Type changed
			*changes = append(*changes, Change{
				Key:         path,
				Description: fmt.Sprintf("%s: type changed", formatPath(path)),
				OldValue:    prev,
				NewValue:    curr,
			})
			return
		}

		// For arrays, compare lengths and values
		if len(prevVal) != len(currArr) {
			*changes = append(*changes, Change{
				Key:         path,
				Description: fmt.Sprintf("%s: count changed %d → %d", formatPath(path), len(prevVal), len(currArr)),
				OldValue:    len(prevVal),
				NewValue:    len(currArr),
			})
		}
		
		// Simple deep equal for arrays (don't recurse into complex arrays)
		if !reflect.DeepEqual(prevVal, currArr) && len(prevVal) == len(currArr) {
			*changes = append(*changes, Change{
				Key:         path,
				Description: fmt.Sprintf("%s: values changed", formatPath(path)),
				OldValue:    prevVal,
				NewValue:    currArr,
			})
		}

	default:
		// Primitive values (string, number, bool)
		if !reflect.DeepEqual(prev, curr) {
			*changes = append(*changes, Change{
				Key:         path,
				Description: fmt.Sprintf("%s: %v → %v", formatPath(path), formatValue(prev), formatValue(curr)),
				OldValue:    prev,
				NewValue:    curr,
			})
		}
	}
}

func getLastKey(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func formatPath(path string) string {
	if path == "" {
		return "root"
	}
	// Convert "security.firewall_enabled" to "Security / Firewall Enabled"
	parts := strings.Split(path, ".")
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(strings.Title(strings.ReplaceAll(p, "_", " ")), " ", " ")
	}
	return strings.Join(parts, " / ")
}

func formatValue(v any) string {
	switch val := v.(type) {
	case string:
		if len(val) > 50 {
			return val[:47] + "..."
		}
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%.2f", val)
	case bool:
		if val {
			return "yes"
		}
		return "no"
	case nil:
		return "none"
	default:
		return fmt.Sprintf("%v", v)
	}
}

// shouldIgnorePath checks if a path should be ignored
// Supports exact match, prefix match (resources.*), and wildcard (*.cpu_*)
func shouldIgnorePath(path string, ignore map[string]bool) bool {
	if path == "" {
		return false
	}
	
	// Exact match
	if ignore[path] {
		return true
	}
	
	// Check each ignore pattern
	for pattern := range ignore {
		// Prefix match: "resources" matches "resources.cpu_percent"
		if strings.HasPrefix(path, pattern+".") || path == pattern {
			return true
		}
		
		// Wildcard: "resources.*" matches "resources.anything"
		if strings.HasSuffix(pattern, ".*") {
			prefix := strings.TrimSuffix(pattern, ".*")
			if strings.HasPrefix(path, prefix+".") || path == prefix {
				return true
			}
		}
		
		// Contains match: "*cpu*" matches "resources.cpuload1"
		if strings.Contains(pattern, "*") {
			// Simple wildcard matching
			parts := strings.Split(pattern, "*")
			match := true
			pos := 0
			for _, part := range parts {
				if part == "" {
					continue
				}
				idx := strings.Index(path[pos:], part)
				if idx == -1 {
					match = false
					break
				}
				pos += idx + len(part)
			}
			if match {
				return true
			}
		}
	}
	
	return false
}
