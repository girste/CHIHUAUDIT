package cis

import (
	"context"
	"strings"

	"github.com/girste/chihuaudit/internal/config"
)

// RunCISAudit executes a CIS benchmark audit for Ubuntu 22.04 LTS
func RunCISAudit(ctx context.Context, level int, includeAllControls bool, wl *config.Whitelist) *CISResult {
	result := NewCISResult("cis-ubuntu-22.04-lts", level)

	// Create checker instance
	checker := NewChecker(ctx, wl)

	// Get controls for the specified level
	var controlDefs []ControlDefinition
	if level == 1 {
		controlDefs = Ubuntu2204Level1Controls(checker)
	} else {
		// Level 2 would include Level 1 + additional controls
		// For now, only Level 1 is implemented
		controlDefs = Ubuntu2204Level1Controls(checker)
	}

	// Track all controls for full output mode
	var allControls []CISControl

	// Section tracking
	sectionStats := make(map[string]*sectionTracker)

	// Execute all controls
	for _, def := range controlDefs {
		control := def.Control

		// Execute the check
		status, evidence := def.Check()
		control.Status = status
		control.Evidence = evidence

		// Track for full output if requested
		if includeAllControls {
			allControls = append(allControls, control)
		}

		// Skip unscored controls for statistics
		if !control.Scored {
			continue
		}

		// Update summary
		result.Summary.Total++
		switch status {
		case StatusPass:
			result.Summary.Passed++
		case StatusFail:
			result.Summary.Failed++
			// Add to failed list (compact format)
			result.Failed = append(result.Failed, FailedControl{
				ID:          control.ID,
				Title:       control.Title,
				Evidence:    control.Evidence,
				Remediation: control.Remediation,
			})
		case StatusNA:
			result.Summary.NA++
		}

		// Update section stats
		sectionID := strings.Split(control.ID, ".")[0]
		tracker, exists := sectionStats[sectionID]
		if !exists {
			tracker = &sectionTracker{name: control.Section}
			sectionStats[sectionID] = tracker
		}
		if status != StatusNA {
			tracker.total++
			if status == StatusPass {
				tracker.passed++
			}
		}
	}

	// Calculate compliance percentage
	scored := result.Summary.Total - result.Summary.NA
	if scored > 0 {
		result.Summary.Pct = roundPct(float64(result.Summary.Passed) / float64(scored) * 100)
	}

	// Build sections map
	for id, tracker := range sectionStats {
		pct := 0.0
		if tracker.total > 0 {
			pct = roundPct(float64(tracker.passed) / float64(tracker.total) * 100)
		}
		result.Sections[id] = SectionSummary{
			Name:   tracker.name,
			Passed: tracker.passed,
			Total:  tracker.total,
			Pct:    pct,
		}
	}

	// Add all controls if requested
	if includeAllControls {
		result.AllControls = allControls
	}

	return result
}

// sectionTracker is used internally to track section statistics
type sectionTracker struct {
	name   string
	passed int
	total  int
}
