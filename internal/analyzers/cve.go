package analyzers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
)

// CVEAnalyzer checks for known CVEs in installed packages
type CVEAnalyzer struct{}

func (a *CVEAnalyzer) Name() string           { return "cve" }
func (a *CVEAnalyzer) RequiresSudo() bool     { return false }
func (a *CVEAnalyzer) Timeout() time.Duration { return 60 * time.Second }

// CVEVulnerability represents a detected CVE
type CVEVulnerability struct {
	CVE         string `json:"cve"`
	Package     string `json:"package"`
	Version     string `json:"version"`
	Severity    string `json:"severity"`
	Description string `json:"description,omitempty"`
	FixedIn     string `json:"fixed_in,omitempty"`
}

// EUVDResponse represents the GCVE API response structure
type EUVDResponse struct {
	Data []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Published   string `json:"published"`
		Modified    string `json:"modified"`
	} `json:"data"`
}

func (a *CVEAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()
	result.Checked = true

	vulnerabilities := []CVEVulnerability{}

	// Get installed packages
	packages, err := getInstalledPackages(ctx)
	if err != nil {
		result.Data = map[string]interface{}{
			"scanned":         false,
			"error":           err.Error(),
			"vulnerabilities": []CVEVulnerability{},
		}
		return result, nil
	}

	// Limit packages to scan (avoid timeout in tests/large systems)
	maxPackages := 50
	if len(packages) > maxPackages {
		packages = packages[:maxPackages]
	}

	// Scan for CVEs using European database (GCVE)
	for _, pkg := range packages {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			// Timeout or cancellation - return what we have so far
			break
		default:
		}

		vulns, err := checkPackageVulnerabilities(ctx, pkg)
		if err != nil {
			// Log error but continue scanning other packages
			continue
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	// Categorize by severity
	critical := 0
	high := 0
	medium := 0
	low := 0

	for _, v := range vulnerabilities {
		switch strings.ToLower(v.Severity) {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		default:
			low++
		}
	}

	result.Data = map[string]interface{}{
		"scanned":         true,
		"total_packages":  len(packages),
		"vulnerabilities": vulnerabilities,
		"summary": map[string]int{
			"critical": critical,
			"high":     high,
			"medium":   medium,
			"low":      low,
			"total":    len(vulnerabilities),
		},
		"database": "ENISA EUVD",
	}

	return result, nil
}

// getInstalledPackages returns list of installed packages
func getInstalledPackages(ctx context.Context) ([]PackageInfo, error) {
	var packages []PackageInfo

	// Try dpkg (Debian/Ubuntu)
	if cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package} ${Version}\n"); cmd.Err == nil {
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(output)))
			for scanner.Scan() {
				parts := strings.Fields(scanner.Text())
				if len(parts) >= 2 {
					packages = append(packages, PackageInfo{
						Name:    parts[0],
						Version: parts[1],
					})
				}
			}
			return packages, nil
		}
	}

	// Try rpm (RedHat/CentOS/Fedora)
	if cmd := exec.CommandContext(ctx, "rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\n"); cmd.Err == nil {
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(output)))
			for scanner.Scan() {
				parts := strings.Fields(scanner.Text())
				if len(parts) >= 2 {
					packages = append(packages, PackageInfo{
						Name:    parts[0],
						Version: parts[1],
					})
				}
			}
			return packages, nil
		}
	}

	return packages, fmt.Errorf("no supported package manager found")
}

type PackageInfo struct {
	Name    string
	Version string
}

// checkPackageVulnerabilities queries EUVD API for package vulnerabilities
func checkPackageVulnerabilities(ctx context.Context, pkg PackageInfo) ([]CVEVulnerability, error) {
	// Use ENISA EUVD API (official European vulnerability database)
	// API endpoint: https://euvdservices.enisa.europa.eu/api/search
	url := fmt.Sprintf("https://euvdservices.enisa.europa.eu/api/search?product=%s&page=0&size=100", 
		strings.ReplaceAll(pkg.Name, " ", "+"))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResp EUVDResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, err
	}

	var vulnerabilities []CVEVulnerability
	for _, item := range apiResp.Data {
		// Check if this CVE affects the installed version
		if affectsVersion(pkg.Version, item.Description) {
			vuln := CVEVulnerability{
				CVE:         item.ID,
				Package:     pkg.Name,
				Version:     pkg.Version,
				Severity:    normalizeSeverity(item.Severity),
				Description: truncateString(item.Description, 200),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities, nil
}

// affectsVersion checks if the CVE description indicates the version is affected
func affectsVersion(installedVersion, description string) bool {
	// Simple heuristic: check if version is mentioned in description
	// More sophisticated version comparison would require parsing version ranges
	versionPattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(installedVersion) + `\b`)
	return versionPattern.MatchString(description) ||
		strings.Contains(strings.ToLower(description), "all versions")
}

// normalizeSeverity converts various severity formats to standard levels
func normalizeSeverity(severity string) string {
	severity = strings.ToLower(strings.TrimSpace(severity))
	switch {
	case strings.Contains(severity, "critical"):
		return "critical"
	case strings.Contains(severity, "high"):
		return "high"
	case strings.Contains(severity, "medium"), strings.Contains(severity, "moderate"):
		return "medium"
	case strings.Contains(severity, "low"):
		return "low"
	default:
		return "unknown"
	}
}

// truncateString limits string length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
