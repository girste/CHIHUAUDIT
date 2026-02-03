package audit

import (
	"context"
	"sync"
	"time"

	"github.com/girste/chihuaudit/internal/analyzers"
	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
	"github.com/girste/chihuaudit/internal/util"
	"go.uber.org/zap"
)

// Orchestrator coordinates the security audit
type Orchestrator struct {
	registry *analyzers.Registry
	logger   *zap.Logger
}

// NewOrchestrator creates a new audit orchestrator
func NewOrchestrator() *Orchestrator {
	registry := analyzers.NewRegistry()

	// Register all analyzers
	registry.Register(&analyzers.FirewallAnalyzer{})
	registry.Register(&analyzers.SSHAnalyzer{})
	registry.Register(&analyzers.ThreatsAnalyzer{})
	registry.Register(&analyzers.DockerAnalyzer{})
	registry.Register(&analyzers.Fail2banAnalyzer{})
	registry.Register(&analyzers.UpdatesAnalyzer{})
	registry.Register(&analyzers.KernelAnalyzer{})
	registry.Register(&analyzers.UsersAnalyzer{})
	registry.Register(&analyzers.ServicesAnalyzer{})
	registry.Register(&analyzers.DiskAnalyzer{})
	registry.Register(&analyzers.MACAnalyzer{})
	registry.Register(&analyzers.SSLAnalyzer{})
	registry.Register(&analyzers.SudoAnalyzer{})
	registry.Register(&analyzers.CronAnalyzer{})
	registry.Register(&analyzers.PermissionsAnalyzer{})
	registry.Register(&analyzers.ProcessAnalyzer{})
	registry.Register(&analyzers.PerformanceAnalyzer{})

	return &Orchestrator{
		registry: registry,
		logger:   util.GetLogger(),
	}
}

// RunAudit executes all enabled analyzers and generates a report
func (o *Orchestrator) RunAudit(ctx context.Context, cfg *config.Config, maskData bool) (map[string]interface{}, error) {
	startTime := time.Now()

	// Execute all analyzers in parallel
	results := o.executeAnalyzers(ctx, cfg)

	// Get OS info
	osInfo := system.GetOSInfo(ctx)

	// Build report
	report := make(map[string]interface{})

	// Metadata section
	metadata := make(map[string]interface{})
	metadata["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	metadata["os"] = osInfo.System + " (" + osInfo.Distro + ")"
	metadata["kernel"] = osInfo.Kernel
	if maskData {
		metadata["hostname"] = util.GetMaskedHostname()
	} else {
		metadata["hostname"] = osInfo.Hostname
	}
	report["metadata"] = metadata

	// Legacy top-level fields for backward compatibility
	report["timestamp"] = metadata["timestamp"]
	report["os"] = metadata["os"]
	report["kernel"] = metadata["kernel"]
	report["hostname"] = metadata["hostname"]

	// Add analyzer results
	for name, result := range results {
		if result != nil {
			// Merge result.Data into a single map for this analyzer
			analyzerOutput := make(map[string]interface{})

			// Add standard fields
			if result.Installed != nil {
				analyzerOutput["installed"] = *result.Installed
			}
			if result.Active != nil {
				analyzerOutput["active"] = *result.Active
			}
			analyzerOutput["checked"] = result.Checked

			if len(result.Issues) > 0 {
				analyzerOutput["issues"] = result.Issues
			}

			// Merge custom data fields
			for k, v := range result.Data {
				analyzerOutput[k] = v
			}

			report[name] = analyzerOutput
		}
	}

	// Generate analysis summary
	analysis := o.generateAnalysis(results)
	report["analysis"] = analysis

	// Generate recommendations
	recommendations := o.generateRecommendations(results)
	report["recommendations"] = recommendations

	duration := time.Since(startTime)
	o.logger.Info("Audit completed", zap.Duration("duration", duration))

	return report, nil
}

// executeAnalyzers runs all enabled analyzers in parallel
func (o *Orchestrator) executeAnalyzers(ctx context.Context, cfg *config.Config) map[string]*analyzers.Result {
	allAnalyzers := o.registry.All()
	results := make(map[string]*analyzers.Result)
	resultsMu := sync.Mutex{}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, cfg.GetMaxConcurrency())

	for _, analyzer := range allAnalyzers {
		if !cfg.IsAnalyzerEnabled(analyzer.Name()) {
			continue
		}

		wg.Add(1)
		go func(a analyzers.Analyzer) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			analyzerCtx, cancel := context.WithTimeout(ctx, a.Timeout())
			defer cancel()

			result, err := a.Analyze(analyzerCtx, cfg)

			if err != nil || result == nil {
				o.logger.Warn("Analyzer failed", zap.String("analyzer", a.Name()), zap.Error(err))
				result = &analyzers.Result{
					Checked: false,
					Issues: []analyzers.Issue{
						{
							Severity: analyzers.SeverityLow,
							Message:  "Analyzer failed to run",
						},
					},
					Data: make(map[string]interface{}),
				}
			}

			resultsMu.Lock()
			results[a.Name()] = result
			resultsMu.Unlock()
		}(analyzer)
	}

	wg.Wait()
	return results
}

// generateAnalysis creates an overall security analysis
func (o *Orchestrator) generateAnalysis(results map[string]*analyzers.Result) map[string]interface{} {
	criticalIssues := 0
	highIssues := 0
	mediumIssues := 0
	lowIssues := 0

	allIssues := []map[string]string{}
	warnings := []string{}

	for _, result := range results {
		for _, issue := range result.Issues {
			switch issue.Severity {
			case analyzers.SeverityCritical:
				criticalIssues++
				allIssues = append(allIssues, map[string]string{
					"severity": string(issue.Severity),
					"message":  issue.Message,
				})
			case analyzers.SeverityHigh:
				highIssues++
				allIssues = append(allIssues, map[string]string{
					"severity": string(issue.Severity),
					"message":  issue.Message,
				})
			case analyzers.SeverityMedium:
				mediumIssues++
				warnings = append(warnings, issue.Message)
			case analyzers.SeverityLow:
				lowIssues++
			}
		}
	}

	overallStatus := "good"
	if criticalIssues > 0 {
		overallStatus = "critical"
	} else if highIssues > 3 {
		overallStatus = "poor"
	} else if highIssues > 0 {
		overallStatus = "fair"
	}

	return map[string]interface{}{
		"overallStatus": overallStatus,
		"summary":       o.generateSummary(overallStatus, criticalIssues, highIssues),
		"issues":        allIssues,
		"warnings":      warnings,
		"score": map[string]int{
			"criticalIssues":     criticalIssues,
			"highPriorityIssues": highIssues,
			"mediumIssues":       mediumIssues,
			"lowIssues":          lowIssues,
		},
	}
}

func (o *Orchestrator) generateSummary(status string, critical, high int) string {
	switch status {
	case "critical":
		return "System has critical security issues that require immediate attention"
	case "poor":
		return "System security needs improvement"
	case "fair":
		return "System security is acceptable but could be improved"
	default:
		return "System security is good"
	}
}

// generateRecommendations creates a list of prioritized recommendations
func (o *Orchestrator) generateRecommendations(results map[string]*analyzers.Result) []string {
	recommendations := []string{}

	for _, result := range results {
		for _, issue := range result.Issues {
			if issue.Recommendation != "" && (issue.Severity == analyzers.SeverityCritical || issue.Severity == analyzers.SeverityHigh) {
				recommendations = append(recommendations, issue.Recommendation)
			}
		}
	}

	// Limit to top 10
	if len(recommendations) > 10 {
		recommendations = recommendations[:10]
	}

	return recommendations
}
