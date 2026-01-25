package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/girste/mcp-cybersec-watchdog/internal/system"
)

const shodanTimeout = 10 * time.Second

// Common ports to scan
var commonPorts = []int{21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017}

// Expected open ports
var expectedPorts = map[int]bool{22: true, 80: true, 443: true}

// Risky service ports
var riskyPorts = map[int]string{
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	27017: "MongoDB",
	9200:  "Elasticsearch",
	5984:  "CouchDB",
	8086:  "InfluxDB",
	3000:  "Common dev server",
	8000:  "Common dev server",
	8080:  "Common dev server",
}

// Service names
var serviceNames = map[int]string{
	21:    "FTP",
	23:    "Telnet",
	25:    "SMTP",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	8080:  "HTTP Alt",
	8443:  "HTTPS Alt",
	27017: "MongoDB",
}

// Precompiled regex for IP validation
var ipv4Regex = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

// NetworkSecurityResult is the result of a network security scan
type NetworkSecurityResult struct {
	ScanCompleted       bool                   `json:"scan_completed"`
	Scope               string                 `json:"scope"`
	Deep                bool                   `json:"deep"`
	AttackerView        bool                   `json:"attacker_view,omitempty"`
	CloudContext        bool                   `json:"cloud_context,omitempty"`
	Local               map[string]interface{} `json:"local,omitempty"`
	External            map[string]interface{} `json:"external,omitempty"`
	AttackerPerspective *AttackerViewResult    `json:"attacker_perspective,omitempty"`
	CloudInfo           *CloudProviderInfo     `json:"cloud_info,omitempty"`
	Issues              []NetworkIssue         `json:"issues"`
	Summary             NetworkSummary         `json:"summary"`
	Error               string                 `json:"error,omitempty"`
}

// AttackerViewResult compares internal vs external visibility
type AttackerViewResult struct {
	Scanned           bool                  `json:"scanned"`
	ExternalService   string                `json:"external_service"`
	LocalPorts        []int                 `json:"local_ports"`
	ExternallyVisible []int                 `json:"externally_visible"`
	FilteredPorts     []int                 `json:"filtered_ports"`
	DiscrepancyFound  bool                  `json:"discrepancy_found"`
	IPReputation      *IPReputationInfo     `json:"ip_reputation,omitempty"`
	ShodanData        *ShodanInternetDBInfo `json:"shodan_data,omitempty"`
}

// IPReputationInfo contains IP reputation check results
type IPReputationInfo struct {
	IP         string   `json:"ip"`
	Clean      bool     `json:"clean"`
	ListedOn   []string `json:"listed_on,omitempty"`
	AbuseScore int      `json:"abuse_score,omitempty"`
}

// ShodanInternetDBInfo contains data from Shodan InternetDB
type ShodanInternetDBInfo struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames,omitempty"`
	CPEs      []string `json:"cpes,omitempty"`
	Vulns     []string `json:"vulns,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

type NetworkIssue struct {
	Severity       string `json:"severity"`
	Type           string `json:"type"`
	Message        string `json:"message"`
	Recommendation string `json:"recommendation"`
}

type NetworkSummary struct {
	TotalIssues int `json:"total_issues"`
	Critical    int `json:"critical"`
	High        int `json:"high"`
	Medium      int `json:"medium"`
	Low         int `json:"low"`
}

// ScanNetworkSecurity analyzes network security posture
func ScanNetworkSecurity(ctx context.Context, scope string, deep bool, attackerView bool, cloudContext bool) *NetworkSecurityResult {
	if scope != "local" && scope != "external" && scope != "both" {
		return &NetworkSecurityResult{
			ScanCompleted: false,
			Error:         "Invalid scope. Use: local, external, or both",
		}
	}

	result := &NetworkSecurityResult{
		ScanCompleted: true,
		Scope:         scope,
		Deep:          deep,
		AttackerView:  attackerView,
		CloudContext:  cloudContext,
		Local:         make(map[string]interface{}),
		External:      make(map[string]interface{}),
		Issues:        []NetworkIssue{},
	}

	// Track local listening ports for comparison
	var localListeningPorts []int

	// Local scanning
	if scope == "local" || scope == "both" {
		localPorts := scanLocalPorts(ctx)
		result.Local["ports"] = localPorts
		result.Issues = append(result.Issues, localPorts["issues"].([]NetworkIssue)...)

		// Extract listening ports for attacker view comparison
		if portsData, ok := localPorts["listening_ports"].([]int); ok {
			localListeningPorts = portsData
		}

		ipv6 := checkIPv6Exposure(ctx)
		result.Local["ipv6"] = ipv6
		if issues, ok := ipv6["issues"].([]NetworkIssue); ok {
			result.Issues = append(result.Issues, issues...)
		}
	}

	// Cloud context detection
	if cloudContext {
		cloudInfo := DetectCloudProvider(ctx)
		result.CloudInfo = cloudInfo

		if cloudInfo.Detected {
			// Add cloud issues
			result.Issues = append(result.Issues, convertCloudIssues(cloudInfo.Issues)...)

			// Compare cloud firewall with local ports if we have local data
			if len(localListeningPorts) > 0 {
				localPortsMap := make(map[int]bool)
				for _, p := range localListeningPorts {
					localPortsMap[p] = true
				}
				cloudIssues := CompareCloudFirewallWithLocal(cloudInfo, localPortsMap)
				result.Issues = append(result.Issues, convertCloudIssues(cloudIssues)...)
			}
		}
	}

	// External scanning
	var publicIP string
	if scope == "external" || scope == "both" {
		publicIP = getPublicIP(ctx)
		result.External["public_ip"] = publicIP

		if publicIP != "" {
			portScan := scanExternalPorts(publicIP)
			result.External["port_scan"] = portScan
			if issues, ok := portScan["issues"].([]NetworkIssue); ok {
				result.Issues = append(result.Issues, issues...)
			}

			if deep {
				sslCheck := checkSSLTLS(ctx, "")
				result.External["ssl_tls"] = sslCheck
				if issues, ok := sslCheck["issues"].([]NetworkIssue); ok {
					result.Issues = append(result.Issues, issues...)
				}

				dnsCheck := checkDNSSecurity(ctx, "")
				result.External["dns_security"] = dnsCheck
				if issues, ok := dnsCheck["issues"].([]NetworkIssue); ok {
					result.Issues = append(result.Issues, issues...)
				}
			}

			// Attacker view scan
			if attackerView {
				attackerResult := performAttackerViewScan(ctx, publicIP, localListeningPorts)
				result.AttackerPerspective = attackerResult

				// Generate issues from attacker perspective
				attackerIssues := generateAttackerViewIssues(attackerResult)
				result.Issues = append(result.Issues, attackerIssues...)
			}
		} else {
			result.External["note"] = "Could not determine public IP"
		}
	}

	// Calculate summary
	critical := 0
	high := 0
	medium := 0
	low := 0
	for _, issue := range result.Issues {
		switch issue.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
	}

	result.Summary = NetworkSummary{
		TotalIssues: len(result.Issues),
		Critical:    critical,
		High:        high,
		Medium:      medium,
		Low:         low,
	}

	return result
}

// convertCloudIssues converts CloudIssue to NetworkIssue
func convertCloudIssues(cloudIssues []CloudIssue) []NetworkIssue {
	var issues []NetworkIssue
	for _, ci := range cloudIssues {
		issues = append(issues, NetworkIssue(ci))
	}
	return issues
}

// performAttackerViewScan uses external services to see what attackers see
func performAttackerViewScan(ctx context.Context, publicIP string, localPorts []int) *AttackerViewResult {
	result := &AttackerViewResult{
		Scanned:         true,
		ExternalService: "shodan_internetdb",
		LocalPorts:      localPorts,
	}

	// Use Shodan InternetDB (free, no API key)
	shodanData := fetchShodanInternetDB(ctx, publicIP)
	result.ShodanData = shodanData

	if shodanData != nil {
		result.ExternallyVisible = shodanData.Ports

		// Compare local vs external visibility
		localPortsMap := make(map[int]bool)
		for _, p := range localPorts {
			localPortsMap[p] = true
		}

		externalPortsMap := make(map[int]bool)
		for _, p := range shodanData.Ports {
			externalPortsMap[p] = true
		}

		// Find discrepancies
		for _, port := range shodanData.Ports {
			if !localPortsMap[port] {
				// Port visible externally but not in our local scan
				result.DiscrepancyFound = true
			}
		}

		// Find filtered ports (local but not external)
		for _, port := range localPorts {
			if !externalPortsMap[port] {
				result.FilteredPorts = append(result.FilteredPorts, port)
			}
		}
	}

	// Check IP reputation
	result.IPReputation = checkIPReputation(ctx, publicIP)

	return result
}

// fetchShodanInternetDB queries the free Shodan InternetDB API
func fetchShodanInternetDB(ctx context.Context, ip string) *ShodanInternetDBInfo {
	client := &http.Client{Timeout: shodanTimeout}
	url := fmt.Sprintf("https://internetdb.shodan.io/%s", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Shodan returns 404 for IPs with no data, which is fine
	if resp.StatusCode == http.StatusNotFound {
		return &ShodanInternetDBInfo{IP: ip, Ports: []int{}}
	}

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var data ShodanInternetDBInfo
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	data.IP = ip
	return &data
}

// checkIPReputation checks if IP is on any blocklists using DNS-based blocklists
func checkIPReputation(ctx context.Context, ip string) *IPReputationInfo {
	info := &IPReputationInfo{
		IP:    ip,
		Clean: true,
	}

	// Validate IPv4
	if !ipv4Regex.MatchString(ip) {
		return info
	}

	// Common DNS-based blocklists
	blocklists := []string{
		"zen.spamhaus.org",
		"bl.spamcop.net",
		"b.barracudacentral.org",
		"dnsbl.sorbs.net",
	}

	// Reverse IP for DNSBL lookup
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return info
	}
	reversed := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]

	for _, bl := range blocklists {
		lookup := reversed + "." + bl
		_, err := net.LookupHost(lookup)
		if err == nil {
			// IP is listed
			info.Clean = false
			info.ListedOn = append(info.ListedOn, bl)
		}
	}

	return info
}

// generateAttackerViewIssues generates issues based on attacker perspective
func generateAttackerViewIssues(av *AttackerViewResult) []NetworkIssue {
	var issues []NetworkIssue

	if av == nil || !av.Scanned {
		return issues
	}

	// Check for known vulnerabilities from Shodan
	if av.ShodanData != nil && len(av.ShodanData.Vulns) > 0 {
		for _, vuln := range av.ShodanData.Vulns {
			issues = append(issues, NetworkIssue{
				Severity:       "critical",
				Type:           "known_cve",
				Message:        fmt.Sprintf("Shodan reports known vulnerability: %s", vuln),
				Recommendation: "Immediately patch or mitigate this vulnerability",
			})
		}
	}

	// Check for unexpected exposed ports
	if av.ShodanData != nil {
		for _, port := range av.ShodanData.Ports {
			if service, ok := riskyPorts[port]; ok {
				// Check if it's not in local ports (might be from old scan)
				found := false
				for _, lp := range av.LocalPorts {
					if lp == port {
						found = true
						break
					}
				}
				if !found {
					issues = append(issues, NetworkIssue{
						Severity:       "high",
						Type:           "port_discrepancy",
						Message:        fmt.Sprintf("%s (port %d) visible in Shodan but not detected locally", service, port),
						Recommendation: "Investigate if this service is running or if it's from cached Shodan data",
					})
				}
			}
		}
	}

	// Check IP reputation
	if av.IPReputation != nil && !av.IPReputation.Clean {
		blocklists := strings.Join(av.IPReputation.ListedOn, ", ")
		issues = append(issues, NetworkIssue{
			Severity:       "medium",
			Type:           "ip_blocklisted",
			Message:        fmt.Sprintf("Server IP is listed on blocklists: %s", blocklists),
			Recommendation: "Request removal from blocklists; this may affect email deliverability and reputation",
		})
	}

	return issues
}

func getPublicIP(ctx context.Context) string {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}

	for _, service := range services {
		result, err := system.RunCommand(ctx, system.TimeoutShort, "curl", "-s", "--max-time", "5", service)
		if err != nil || result == nil || !result.Success {
			continue
		}

		ip := strings.TrimSpace(result.Stdout)
		if ipv4Regex.MatchString(ip) {
			return ip
		}
	}

	return ""
}

func scanLocalPorts(ctx context.Context) map[string]interface{} {
	var issues []NetworkIssue

	result, err := system.RunCommandSudo(ctx, system.TimeoutShort, "ss", "-tulpn")
	if err != nil || result == nil || !result.Success {
		// Fallback to netstat
		result, err = system.RunCommandSudo(ctx, system.TimeoutShort, "netstat", "-tulpn")
		if err != nil || result == nil {
			return map[string]interface{}{
				"scanned": false,
				"error":   "Failed to scan ports (ss/netstat not available)",
				"issues":  issues,
			}
		}
	}

	var listeningPorts []map[string]interface{}
	var wildcardBindings []map[string]interface{}

	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		if !strings.Contains(line, "LISTEN") && !strings.Contains(line, "UNCONN") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		localAddr := fields[4]
		parts := strings.Split(localAddr, ":")
		if len(parts) < 2 {
			continue
		}

		portStr := parts[len(parts)-1]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		addr := strings.Join(parts[:len(parts)-1], ":")

		listeningPorts = append(listeningPorts, map[string]interface{}{
			"port":    port,
			"address": addr,
		})

		// Check wildcard bindings
		if addr == "0.0.0.0" || addr == "*" || addr == "::" || addr == "[::]" {
			if service, ok := riskyPorts[port]; ok {
				wildcardBindings = append(wildcardBindings, map[string]interface{}{
					"port":    port,
					"service": service,
					"address": addr,
				})
				issues = append(issues, NetworkIssue{
					Severity:       "high",
					Type:           "exposed_service",
					Message:        fmt.Sprintf("%s (port %d) listening on all interfaces", service, port),
					Recommendation: "Bind to 127.0.0.1 only or use firewall to restrict access",
				})
			}
		}
	}

	// Extract port numbers for attacker view comparison
	var portNumbers []int
	for _, lp := range listeningPorts {
		if port, ok := lp["port"].(int); ok {
			portNumbers = append(portNumbers, port)
		}
	}

	return map[string]interface{}{
		"scanned":           true,
		"total_listening":   len(listeningPorts),
		"wildcard_bindings": len(wildcardBindings),
		"risky_exposed":     wildcardBindings,
		"listening_ports":   portNumbers,
		"issues":            issues,
	}
}

func checkIPv6Exposure(ctx context.Context) map[string]interface{} {
	var issues []NetworkIssue

	result, err := system.RunCommand(ctx, system.TimeoutShort, "ss", "-tulpn6")
	if err != nil || result == nil {
		return map[string]interface{}{
			"scanned": false,
			"note":    "IPv6 check skipped",
		}
	}

	ipv6Listeners := 0
	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		if strings.Contains(line, "LISTEN") && strings.Contains(line, "::") {
			ipv6Listeners++
		}
	}

	if ipv6Listeners > 0 {
		issues = append(issues, NetworkIssue{
			Severity:       "low",
			Type:           "ipv6_exposure",
			Message:        fmt.Sprintf("%d services listening on IPv6", ipv6Listeners),
			Recommendation: "Ensure IPv6 firewall rules are configured if IPv6 is not needed",
		})
	}

	return map[string]interface{}{
		"scanned":        true,
		"ipv6_listeners": ipv6Listeners,
		"issues":         issues,
	}
}

func scanExternalPorts(publicIP string) map[string]interface{} {
	var issues []NetworkIssue
	var openPorts []int

	for _, port := range commonPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", publicIP, port), 2*time.Second)
		if err == nil {
			_ = conn.Close()
			openPorts = append(openPorts, port)

			if !expectedPorts[port] {
				severity := "medium"
				if port == 21 || port == 23 || port == 3306 || port == 5432 || port == 6379 || port == 27017 {
					severity = "high"
				}

				serviceName := serviceNames[port]
				if serviceName == "" {
					serviceName = "Unknown"
				}

				issues = append(issues, NetworkIssue{
					Severity:       severity,
					Type:           "unexpected_open_port",
					Message:        fmt.Sprintf("Port %d (%s) is publicly accessible", port, serviceName),
					Recommendation: "Close port with firewall if not intentionally exposed",
				})
			}
		}
	}

	return map[string]interface{}{
		"scanned":    true,
		"public_ip":  publicIP,
		"open_ports": openPorts,
		"total_open": len(openPorts),
		"issues":     issues,
	}
}

func checkSSLTLS(ctx context.Context, domain string) map[string]interface{} {
	var issues []NetworkIssue

	if domain == "" {
		result, err := system.RunCommand(ctx, system.TimeoutShort, "hostname", "-f")
		if err == nil && result != nil && result.Success {
			domain = strings.TrimSpace(result.Stdout)
		}
	}

	if domain == "" || domain == "localhost" {
		return map[string]interface{}{
			"scanned": false,
			"note":    "No domain detected for SSL check",
		}
	}

	result, err := system.RunCommand(ctx, system.TimeoutMedium, "openssl", "s_client",
		"-connect", domain+":443", "-servername", domain)
	if err != nil || result == nil {
		return map[string]interface{}{
			"scanned": false,
			"domain":  domain,
			"note":    "SSL connection failed",
		}
	}

	output := result.Stdout + result.Stderr
	certInfo := make(map[string]interface{})

	// Check protocol
	if strings.Contains(output, "TLSv1.3") {
		certInfo["protocol"] = "TLSv1.3"
	} else if strings.Contains(output, "TLSv1.2") {
		certInfo["protocol"] = "TLSv1.2"
	} else if strings.Contains(output, "TLSv1.1") || strings.Contains(output, "TLSv1 ") {
		certInfo["protocol"] = "TLSv1.0/1.1"
		issues = append(issues, NetworkIssue{
			Severity:       "high",
			Type:           "weak_tls",
			Message:        "Server supports TLS 1.0/1.1 (deprecated)",
			Recommendation: "Disable TLS 1.0/1.1, use TLS 1.2+ only",
		})
	}

	// Check weak ciphers
	weakCiphers := []string{"RC4", "DES", "MD5", "NULL", "EXPORT", "anon"}
	for _, cipher := range weakCiphers {
		if strings.Contains(output, cipher) {
			issues = append(issues, NetworkIssue{
				Severity:       "critical",
				Type:           "weak_cipher",
				Message:        "Weak cipher suite detected: " + cipher,
				Recommendation: "Disable weak cipher suites in SSL/TLS configuration",
			})
			break
		}
	}

	return map[string]interface{}{
		"scanned":     true,
		"domain":      domain,
		"certificate": certInfo,
		"issues":      issues,
	}
}

func checkDNSSecurity(ctx context.Context, domain string) map[string]interface{} {
	var issues []NetworkIssue

	if domain == "" {
		result, err := system.RunCommand(ctx, system.TimeoutShort, "hostname", "-f")
		if err == nil && result != nil && result.Success {
			domain = strings.TrimSpace(result.Stdout)
		}
	}

	if domain == "" || domain == "localhost" || !strings.Contains(domain, ".") {
		return map[string]interface{}{
			"scanned": false,
			"note":    "No valid domain for DNS security check",
		}
	}

	records := make(map[string]bool)

	// Check SPF
	spfResult, _ := system.RunCommand(ctx, system.TimeoutShort, "dig", "+short", "TXT", domain)
	if spfResult != nil && spfResult.Success {
		spfFound := strings.Contains(spfResult.Stdout, "v=spf1")
		records["spf"] = spfFound
		if !spfFound {
			issues = append(issues, NetworkIssue{
				Severity:       "medium",
				Type:           "missing_spf",
				Message:        "No SPF record found",
				Recommendation: "Add SPF record to prevent email spoofing",
			})
		}
	}

	// Check DMARC
	dmarcResult, _ := system.RunCommand(ctx, system.TimeoutShort, "dig", "+short", "TXT", "_dmarc."+domain)
	if dmarcResult != nil && dmarcResult.Success {
		dmarcFound := strings.Contains(dmarcResult.Stdout, "v=DMARC1")
		records["dmarc"] = dmarcFound
		if !dmarcFound {
			issues = append(issues, NetworkIssue{
				Severity:       "medium",
				Type:           "missing_dmarc",
				Message:        "No DMARC record found",
				Recommendation: "Add DMARC record for email authentication",
			})
		}
	}

	// Check CAA
	caaResult, _ := system.RunCommand(ctx, system.TimeoutShort, "dig", "+short", "CAA", domain)
	if caaResult != nil && caaResult.Success {
		caaFound := strings.TrimSpace(caaResult.Stdout) != ""
		records["caa"] = caaFound
		if !caaFound {
			issues = append(issues, NetworkIssue{
				Severity:       "low",
				Type:           "missing_caa",
				Message:        "No CAA record found",
				Recommendation: "Add CAA record to control SSL certificate issuance",
			})
		}
	}

	return map[string]interface{}{
		"scanned": true,
		"domain":  domain,
		"records": records,
		"issues":  issues,
	}
}
