package output

import (
	"testing"
)

// FuzzFormatterReport tests report formatting with random map data
func FuzzFormatterReport(f *testing.F) {
	// Seed with basic report structures
	f.Add("hostname1", int64(85), "firewall", "status")
	f.Add("", int64(0), "", "")
	f.Add("test-server", int64(100), "ssh", "enabled")

	f.Fuzz(func(t *testing.T, hostname string, score int64, key string, value string) {
		// Create various report structures
		reports := []map[string]interface{}{
			{"hostname": hostname, "score": score},
			{key: value},
			{"negatives": []interface{}{
				map[string]interface{}{"severity": "high", "message": value},
			}},
			{},
		}

		formatter := NewFormatter("json", false, false)

		for _, report := range reports {
			// Should not panic on any report structure
			_ = formatter.FormatReport(report)
		}
	})
}

// FuzzTrafficLightDetermination tests traffic light status calculation
func FuzzTrafficLightDetermination(f *testing.F) {
	f.Add(100, 0, "")
	f.Add(0, 10, "critical")
	f.Add(85, 1, "high")
	f.Add(-50, 0, "")
	f.Add(200, 100, "low")

	f.Fuzz(func(t *testing.T, score int, negCount int, severity string) {
		negatives := make([]NegativeItem, 0)
		for i := 0; i < negCount && i < 1000; i++ {
			negatives = append(negatives, NegativeItem{
				Severity: severity,
				Message:  "test",
			})
		}

		formatter := NewFormatter("text", false, false)
		// Should not panic on edge cases
		_ = formatter.determineTrafficLight(score, negatives)
	})
}

// FuzzScoreCalculation tests score calculation with edge cases
func FuzzScoreCalculation(f *testing.F) {
	f.Add(100, 0, "low")
	f.Add(0, 100, "critical")
	f.Add(-100, 50, "high")

	f.Fuzz(func(t *testing.T, baseScore int, negCount int, severity string) {
		negatives := make([]NegativeItem, 0)
		for i := 0; i < negCount && i < 500; i++ {
			negatives = append(negatives, NegativeItem{
				Severity: severity,
				Message:  "test message",
			})
		}

		formatter := NewFormatter("json", false, false)
		// Should not panic on edge cases
		_ = formatter.calculateScore(baseScore, negatives)
	})
}
