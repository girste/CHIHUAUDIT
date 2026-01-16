package scanners

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/girste/mcp-cybersec-watchdog/internal/system"
)

const (
	maxAppsToScan      = 10
	maxFileSize        = 1_000_000
	maxSearchDepth     = 3
	scanTimeoutSeconds = 30
)

// Stack detection patterns
var stackPatterns = map[string][]string{
	"nodejs": {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
	"python": {"requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py"},
	"rust":   {"Cargo.toml", "Cargo.lock"},
	"go":     {"go.mod", "go.sum"},
	"php":    {"composer.json", "composer.lock"},
	"java":   {"pom.xml", "build.gradle", "build.gradle.kts"},
	"ruby":   {"Gemfile", "Gemfile.lock"},
	"dotnet": {".csproj", ".fsproj", ".vbproj"},
}

// Secret detection patterns
var secretPatterns = map[string]*regexp.Regexp{
	"AWS Access Key":  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"GitHub Token":    regexp.MustCompile(`gh[pousr]_[0-9a-zA-Z]{36}`),
	"Generic API Key": regexp.MustCompile(`(?i)api[_-]?key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']`),
	"Generic Secret":  regexp.MustCompile(`(?i)secret["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']`),
	"Password":        regexp.MustCompile(`(?i)password["']?\s*[:=]\s*["']([^"']{8,})["']`),
	"Private Key":     regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`),
	"Generic Token":   regexp.MustCompile(`(?i)token["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']`),
}

// Directories to exclude
var excludeDirs = map[string]bool{
	"node_modules": true, "venv": true, ".venv": true, "env": true,
	".git": true, "__pycache__": true, "dist": true, "build": true,
	"vendor": true, "target": true,
}

// Code extensions to scan
var codeExtensions = map[string]bool{
	".js": true, ".ts": true, ".py": true, ".rb": true, ".php": true,
	".go": true, ".rs": true, ".java": true, ".cs": true, ".env": true,
	".config": true, ".yml": true, ".yaml": true, ".json": true,
}

// AppSecurityResult is the result of an app security scan
type AppSecurityResult struct {
	ScanCompleted       bool               `json:"scan_completed"`
	Depth               string             `json:"depth"`
	ApplicationsFound   int                `json:"applications_found"`
	ApplicationsScanned int                `json:"applications_scanned"`
	Summary             AppSecuritySummary `json:"summary"`
	Applications        []ScannedApp       `json:"applications"`
	Issues              []AppSecurityIssue `json:"issues"`
	Note                string             `json:"note,omitempty"`
	Error               string             `json:"error,omitempty"`
}

type AppSecuritySummary struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	TotalSecretsFound    int `json:"total_secrets_found"`
	CriticalIssues       int `json:"critical_issues"`
	HighIssues           int `json:"high_issues"`
}

type ScannedApp struct {
	Name         string                 `json:"name"`
	Path         string                 `json:"path"`
	Stacks       []string               `json:"stacks"`
	Dependencies map[string]interface{} `json:"dependencies"`
	Secrets      map[string]interface{} `json:"secrets,omitempty"`
	Config       map[string]interface{} `json:"config,omitempty"`
}

type AppSecurityIssue struct {
	Severity       string `json:"severity"`
	Message        string `json:"message"`
	Recommendation string `json:"recommendation,omitempty"`
}

type detectedApp struct {
	path   string
	name   string
	stacks []string
}

// ScanAppSecurity scans applications for security vulnerabilities
func ScanAppSecurity(ctx context.Context, path string, depth string) *AppSecurityResult {
	if depth != "quick" && depth != "standard" && depth != "deep" {
		return &AppSecurityResult{
			ScanCompleted: false,
			Error:         "Invalid depth parameter. Use: quick, standard, or deep",
		}
	}

	var apps []detectedApp

	if path != "" {
		// Specific path
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			return &AppSecurityResult{
				ScanCompleted: false,
				Error:         "Path not found or not a directory: " + path,
			}
		}
		stacks := detectStack(path)
		apps = []detectedApp{{path: path, name: filepath.Base(path), stacks: stacks}}
	} else {
		// Auto-detect
		searchPaths := getDefaultSearchPaths()
		apps = findApplications(searchPaths, maxSearchDepth)
	}

	if len(apps) == 0 {
		return &AppSecurityResult{
			ScanCompleted:     true,
			ApplicationsFound: 0,
			Note:              "No applications detected. Supported stacks: Node.js, Python, Rust, Go, PHP, Java, Ruby, .NET",
		}
	}

	// Scan each application
	var scannedApps []ScannedApp
	var issues []AppSecurityIssue
	totalVulns := 0
	totalSecrets := 0

	limit := maxAppsToScan
	if len(apps) < limit {
		limit = len(apps)
	}

	for _, app := range apps[:limit] {
		scanned := ScannedApp{
			Name:         app.name,
			Path:         app.path,
			Stacks:       app.stacks,
			Dependencies: make(map[string]interface{}),
		}

		// Scan dependencies
		for _, stack := range app.stacks {
			var depScan map[string]interface{}

			switch stack {
			case "nodejs":
				depScan = scanNodeDeps(ctx, app.path)
			case "python":
				depScan = scanPythonDeps(ctx, app.path)
			case "rust":
				depScan = scanRustDeps(ctx, app.path)
			case "go":
				depScan = scanGoDeps(ctx, app.path)
			}

			if depScan != nil {
				scanned.Dependencies[stack] = depScan
				if vulns, ok := depScan["vulnerabilities"].(int); ok && vulns > 0 {
					totalVulns += vulns
					severity := "medium"
					if critical, ok := depScan["critical"].(int); ok && critical > 0 {
						severity = "high"
					}
					issues = append(issues, AppSecurityIssue{
						Severity:       severity,
						Message:        app.name + ": " + stack + " vulnerabilities found",
						Recommendation: "Run dependency audit and update vulnerable packages",
					})
				}
			}
		}

		// Scan for secrets (standard/deep only)
		if depth == "standard" || depth == "deep" {
			secretsScan := scanSecrets(app.path, depth)
			scanned.Secrets = secretsScan
			if found, ok := secretsScan["secrets_found"].(int); ok && found > 0 {
				totalSecrets += found
				issues = append(issues, AppSecurityIssue{
					Severity:       "critical",
					Message:        app.name + ": potential secrets found in code",
					Recommendation: "Remove hardcoded secrets, use environment variables",
				})
			}

			// Check config issues
			configCheck := checkConfigIssues(app.path)
			scanned.Config = configCheck
			if configIssues, ok := configCheck["issues"].([]map[string]string); ok {
				for _, issue := range configIssues {
					issues = append(issues, AppSecurityIssue{
						Severity:       issue["severity"],
						Message:        issue["message"],
						Recommendation: issue["recommendation"],
					})
				}
			}
		}

		scannedApps = append(scannedApps, scanned)
	}

	// Count issues by severity
	criticalCount := 0
	highCount := 0
	for _, issue := range issues {
		if issue.Severity == "critical" {
			criticalCount++
		} else if issue.Severity == "high" {
			highCount++
		}
	}

	return &AppSecurityResult{
		ScanCompleted:       true,
		Depth:               depth,
		ApplicationsFound:   len(apps),
		ApplicationsScanned: len(scannedApps),
		Summary: AppSecuritySummary{
			TotalVulnerabilities: totalVulns,
			TotalSecretsFound:    totalSecrets,
			CriticalIssues:       criticalCount,
			HighIssues:           highCount,
		},
		Applications: scannedApps,
		Issues:       issues,
		Note:         "Install scanning tools for full coverage: pip install pip-audit, cargo install cargo-audit",
	}
}

func getDefaultSearchPaths() []string {
	var paths []string

	if home := os.Getenv("HOME"); home != "" {
		if info, err := os.Stat(home); err == nil && info.IsDir() {
			paths = append(paths, home)
		}
	}

	commonDirs := []string{"/var/www", "/opt", "/srv"}
	for _, dir := range commonDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			paths = append(paths, dir)
		}
	}

	return paths
}

func detectStack(dir string) []string {
	var detected []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return detected
	}

	files := make(map[string]bool)
	for _, entry := range entries {
		if !entry.IsDir() {
			files[entry.Name()] = true
		}
	}

	for stack, patterns := range stackPatterns {
		for _, pattern := range patterns {
			if files[pattern] {
				detected = append(detected, stack)
				break
			}
		}
	}

	return detected
}

func findApplications(searchPaths []string, maxDepth int) []detectedApp {
	var apps []detectedApp

	var walk func(path string, depth int)
	walk = func(path string, depth int) {
		if depth > maxDepth || len(apps) >= maxAppsToScan*2 {
			return
		}

		entries, err := os.ReadDir(path)
		if err != nil {
			return
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if excludeDirs[entry.Name()] {
				continue
			}

			fullPath := filepath.Join(path, entry.Name())
			stacks := detectStack(fullPath)
			if len(stacks) > 0 {
				apps = append(apps, detectedApp{
					path:   fullPath,
					name:   entry.Name(),
					stacks: stacks,
				})
			}

			walk(fullPath, depth+1)
		}
	}

	for _, searchPath := range searchPaths {
		walk(searchPath, 0)
	}

	return apps
}

func scanNodeDeps(ctx context.Context, appPath string) map[string]interface{} {
	pkgJSON := filepath.Join(appPath, "package.json")
	if _, err := os.Stat(pkgJSON); err != nil {
		return nil
	}

	result, err := system.RunCommand(ctx, system.TimeoutLong, "npm", "audit", "--json")
	if err != nil || result == nil {
		return map[string]interface{}{
			"scanned":         false,
			"error":           "npm audit failed or npm not installed",
			"vulnerabilities": 0,
		}
	}

	var auditData map[string]interface{}
	if err := json.Unmarshal([]byte(result.Stdout), &auditData); err != nil {
		return map[string]interface{}{
			"scanned":         false,
			"error":           "Failed to parse npm audit output",
			"vulnerabilities": 0,
		}
	}

	// Parse npm 7+ format
	if vulns, ok := auditData["vulnerabilities"].(map[string]interface{}); ok {
		critical := 0
		high := 0
		moderate := 0
		low := 0
		total := 0

		for _, v := range vulns {
			total++
			if vMap, ok := v.(map[string]interface{}); ok {
				if sev, ok := vMap["severity"].(string); ok {
					switch sev {
					case "critical":
						critical++
					case "high":
						high++
					case "moderate":
						moderate++
					case "low":
						low++
					}
				}
			}
		}

		return map[string]interface{}{
			"scanned":         true,
			"vulnerabilities": total,
			"critical":        critical,
			"high":            high,
			"moderate":        moderate,
			"low":             low,
		}
	}

	return map[string]interface{}{
		"scanned":         true,
		"vulnerabilities": 0,
	}
}

func scanPythonDeps(ctx context.Context, appPath string) map[string]interface{} {
	reqFiles := []string{"requirements.txt", "Pipfile", "pyproject.toml"}
	hasDeps := false
	for _, f := range reqFiles {
		if _, err := os.Stat(filepath.Join(appPath, f)); err == nil {
			hasDeps = true
			break
		}
	}
	if !hasDeps {
		return nil
	}

	// Try pip-audit
	result, err := system.RunCommand(ctx, system.TimeoutLong, "pip-audit", "--format", "json", "-r", filepath.Join(appPath, "requirements.txt"))
	if err != nil || result == nil || !result.Success {
		return map[string]interface{}{
			"scanned":         false,
			"error":           "pip-audit failed or not installed (pip install pip-audit)",
			"vulnerabilities": 0,
		}
	}

	var auditData map[string]interface{}
	if err := json.Unmarshal([]byte(result.Stdout), &auditData); err != nil {
		return map[string]interface{}{
			"scanned":         false,
			"error":           "Failed to parse pip-audit output",
			"vulnerabilities": 0,
		}
	}

	if vulns, ok := auditData["vulnerabilities"].([]interface{}); ok {
		return map[string]interface{}{
			"scanned":         true,
			"vulnerabilities": len(vulns),
		}
	}

	return map[string]interface{}{
		"scanned":         true,
		"vulnerabilities": 0,
	}
}

func scanRustDeps(ctx context.Context, appPath string) map[string]interface{} {
	cargoToml := filepath.Join(appPath, "Cargo.toml")
	if _, err := os.Stat(cargoToml); err != nil {
		return nil
	}

	result, err := system.RunCommand(ctx, system.TimeoutLong, "cargo", "audit", "--json")
	if err != nil || result == nil {
		return map[string]interface{}{
			"scanned":         false,
			"error":           "cargo audit failed or not installed (cargo install cargo-audit)",
			"vulnerabilities": 0,
		}
	}

	var auditData map[string]interface{}
	if err := json.Unmarshal([]byte(result.Stdout), &auditData); err != nil {
		return map[string]interface{}{
			"scanned":         true,
			"vulnerabilities": 0,
		}
	}

	if vulns, ok := auditData["vulnerabilities"].(map[string]interface{}); ok {
		if list, ok := vulns["list"].([]interface{}); ok {
			return map[string]interface{}{
				"scanned":         true,
				"vulnerabilities": len(list),
			}
		}
	}

	return map[string]interface{}{
		"scanned":         true,
		"vulnerabilities": 0,
	}
}

func scanGoDeps(ctx context.Context, appPath string) map[string]interface{} {
	goMod := filepath.Join(appPath, "go.mod")
	if _, err := os.Stat(goMod); err != nil {
		return nil
	}

	// govulncheck
	result, err := system.RunCommand(ctx, system.TimeoutLong, "govulncheck", "-json", "./...")
	if err != nil || result == nil {
		return map[string]interface{}{
			"scanned":         false,
			"error":           "govulncheck failed or not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)",
			"vulnerabilities": 0,
		}
	}

	// Count vulnerabilities from output
	vulnCount := strings.Count(result.Stdout, `"OSV":`)

	return map[string]interface{}{
		"scanned":         true,
		"vulnerabilities": vulnCount,
	}
}

func scanSecrets(appPath string, depth string) map[string]interface{} {
	if depth == "quick" {
		return map[string]interface{}{
			"scanned": false,
			"reason":  "secrets scan requires depth=standard or depth=deep",
		}
	}

	var secretsFound []map[string]interface{}
	filesScanned := 0

	_ = filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip directories
		if info.IsDir() {
			if excludeDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip large files
		if info.Size() > maxFileSize {
			return nil
		}

		// Only scan code files
		ext := filepath.Ext(path)
		if !codeExtensions[ext] {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		filesScanned++

		relPath, _ := filepath.Rel(appPath, path)

		for secretType, pattern := range secretPatterns {
			matches := pattern.FindAllString(string(content), -1)
			if len(matches) > 0 {
				secretsFound = append(secretsFound, map[string]interface{}{
					"type":    secretType,
					"file":    relPath,
					"matches": len(matches),
				})
			}
		}

		return nil
	})

	result := map[string]interface{}{
		"scanned":       true,
		"files_scanned": filesScanned,
		"secrets_found": len(secretsFound),
	}

	if depth == "deep" {
		result["secrets"] = secretsFound
	}

	return result
}

func checkConfigIssues(appPath string) map[string]interface{} {
	var issues []map[string]string

	// Check for .env in public directories
	publicDirs := map[string]bool{"public": true, "static": true, "dist": true, "build": true}

	_ = filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if strings.HasPrefix(info.Name(), ".env") {
			// Check if in public directory
			for parent := filepath.Dir(path); parent != appPath; parent = filepath.Dir(parent) {
				if publicDirs[filepath.Base(parent)] {
					relPath, _ := filepath.Rel(appPath, path)
					issues = append(issues, map[string]string{
						"severity":       "high",
						"type":           "exposed_secrets",
						"message":        ".env file in public directory: " + relPath,
						"recommendation": "Move .env files outside public directories",
					})
					break
				}
			}
		}

		return nil
	})

	return map[string]interface{}{
		"checked":      true,
		"issues_found": len(issues),
		"issues":       issues,
	}
}
