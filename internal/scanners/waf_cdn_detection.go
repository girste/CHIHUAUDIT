package scanners

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"time"
)

// WAFCDNResult is the result of WAF/CDN detection
type WAFCDNResult struct {
	ScanCompleted   bool                `json:"scan_completed"`
	Domain          string              `json:"domain"`
	Detection       WAFCDNDetection     `json:"detection"`
	Headers         map[string][]string `json:"headers,omitempty"`
	DNSInfo         DNSChainInfo        `json:"dns_info"`
	IPInfo          IPRangeInfo         `json:"ip_info"`
	SecurityPosture WAFSecurityPosture  `json:"security_posture"`
	Issues          []WAFCDNIssue       `json:"issues"`
	Summary         WAFCDNSummary       `json:"summary"`
	Error           string              `json:"error,omitempty"`
}

// WAFCDNDetection contains detection results
type WAFCDNDetection struct {
	Provider         string   `json:"provider"`
	ProviderName     string   `json:"provider_name"`
	Type             string   `json:"type"`
	Confidence       string   `json:"confidence"`
	DetectionMethods []string `json:"detection_methods"`
}

// DNSChainInfo contains DNS resolution information
type DNSChainInfo struct {
	Scanned       bool     `json:"scanned"`
	CNAMEChain    []string `json:"cname_chain"`
	FinalIPs      []string `json:"final_ips"`
	ProviderHints []string `json:"provider_hints"`
}

// IPRangeInfo contains IP range matching results
type IPRangeInfo struct {
	IP              string `json:"ip"`
	MatchedProvider string `json:"matched_provider,omitempty"`
	ASN             string `json:"asn,omitempty"`
	ASNOrg          string `json:"asn_org,omitempty"`
}

// WAFSecurityPosture represents the security posture analysis
type WAFSecurityPosture struct {
	ProtectedByWAF  bool   `json:"protected_by_waf"`
	ProtectedByCDN  bool   `json:"protected_by_cdn"`
	OriginExposed   bool   `json:"origin_exposed"`
	EdgeCaching     bool   `json:"edge_caching"`
	DDoSProtection  string `json:"ddos_protection"`
	SSLTermination  string `json:"ssl_termination"`
	BotProtection   bool   `json:"bot_protection"`
	RateLimiting    bool   `json:"rate_limiting"`
}

// WAFCDNIssue represents a security issue found
type WAFCDNIssue struct {
	Severity       string `json:"severity"`
	Type           string `json:"type"`
	Message        string `json:"message"`
	Recommendation string `json:"recommendation"`
}

// WAFCDNSummary contains a summary of the scan
type WAFCDNSummary struct {
	Protected      bool   `json:"protected"`
	Provider       string `json:"provider"`
	IssueCount     int    `json:"issue_count"`
	CriticalIssues int    `json:"critical_issues"`
	HighIssues     int    `json:"high_issues"`
}

// CDNProvider represents a CDN/WAF provider's detection signatures
type CDNProvider struct {
	Name        string
	Type        string // waf, cdn, waf+cdn
	Headers     []HeaderSignature
	Cookies     []string
	DNSPatterns []string
	IPRangeURL  string
}

// HeaderSignature represents a header pattern to match
type HeaderSignature struct {
	Name    string
	Pattern *regexp.Regexp
}

// Known CDN/WAF providers with detection signatures
var cdnProviders = map[string]CDNProvider{
	"cloudflare": {
		Name: "Cloudflare",
		Type: "waf+cdn",
		Headers: []HeaderSignature{
			{Name: "cf-ray", Pattern: regexp.MustCompile(`.*`)},
			{Name: "cf-cache-status", Pattern: regexp.MustCompile(`.*`)},
			{Name: "server", Pattern: regexp.MustCompile(`(?i)cloudflare`)},
			{Name: "cf-request-id", Pattern: regexp.MustCompile(`.*`)},
		},
		Cookies:     []string{"__cfduid", "__cf_bm", "cf_clearance"},
		DNSPatterns: []string{".cloudflare.com", ".cloudflare-dns.com", ".cloudflaressl.com"},
		IPRangeURL:  "https://www.cloudflare.com/ips-v4",
	},
	"aws_cloudfront": {
		Name: "AWS CloudFront",
		Type: "cdn",
		Headers: []HeaderSignature{
			{Name: "x-amz-cf-id", Pattern: regexp.MustCompile(`.*`)},
			{Name: "x-amz-cf-pop", Pattern: regexp.MustCompile(`.*`)},
			{Name: "via", Pattern: regexp.MustCompile(`(?i)cloudfront`)},
			{Name: "x-cache", Pattern: regexp.MustCompile(`(?i)cloudfront`)},
		},
		DNSPatterns: []string{".cloudfront.net"},
		IPRangeURL:  "https://ip-ranges.amazonaws.com/ip-ranges.json",
	},
	"aws_waf": {
		Name: "AWS WAF",
		Type: "waf",
		Headers: []HeaderSignature{
			{Name: "x-amzn-waf-action", Pattern: regexp.MustCompile(`.*`)},
			{Name: "x-amzn-requestid", Pattern: regexp.MustCompile(`.*`)},
		},
	},
	"akamai": {
		Name: "Akamai",
		Type: "waf+cdn",
		Headers: []HeaderSignature{
			{Name: "x-akamai-transformed", Pattern: regexp.MustCompile(`.*`)},
			{Name: "akamai-grn", Pattern: regexp.MustCompile(`.*`)},
			{Name: "x-akamai-request-id", Pattern: regexp.MustCompile(`.*`)},
			{Name: "server", Pattern: regexp.MustCompile(`(?i)akamaighost`)},
		},
		DNSPatterns: []string{".akamaiedge.net", ".akamai.net", ".edgekey.net", ".edgesuite.net"},
	},
	"azure_cdn": {
		Name: "Azure CDN",
		Type: "cdn",
		Headers: []HeaderSignature{
			{Name: "x-azure-ref", Pattern: regexp.MustCompile(`.*`)},
			{Name: "x-ms-ref", Pattern: regexp.MustCompile(`.*`)},
			{Name: "x-azure-cache", Pattern: regexp.MustCompile(`.*`)},
		},
		DNSPatterns: []string{".azureedge.net", ".azure.com", ".msecnd.net", ".vo.msecnd.net"},
	},
	"azure_front_door": {
		Name: "Azure Front Door",
		Type: "waf+cdn",
		Headers: []HeaderSignature{
			{Name: "x-azure-ref", Pattern: regexp.MustCompile(`.*`)},
			{Name: "x-fd-healthprobe", Pattern: regexp.MustCompile(`.*`)},
		},
		DNSPatterns: []string{".azurefd.net", ".afd.ms"},
	},
	"fastly": {
		Name: "Fastly",
		Type: "cdn",
		Headers: []HeaderSignature{
			{Name: "x-served-by", Pattern: regexp.MustCompile(`cache-`)},
			{Name: "x-fastly-request-id", Pattern: regexp.MustCompile(`.*`)},
			{Name: "fastly-debug-digest", Pattern: regexp.MustCompile(`.*`)},
			{Name: "x-cache", Pattern: regexp.MustCompile(`(?i)fastly`)},
		},
		DNSPatterns: []string{".fastly.net", ".fastlylb.net", ".fastly-edge.com"},
	},
	"imperva": {
		Name: "Imperva/Incapsula",
		Type: "waf+cdn",
		Headers: []HeaderSignature{
			{Name: "x-iinfo", Pattern: regexp.MustCompile(`.*`)},
			{Name: "x-cdn", Pattern: regexp.MustCompile(`(?i)incapsula|imperva`)},
		},
		Cookies:     []string{"incap_ses_", "visid_incap_", "nlbi_"},
		DNSPatterns: []string{".incapdns.net", ".impervadns.net"},
	},
	"sucuri": {
		Name: "Sucuri",
		Type: "waf",
		Headers: []HeaderSignature{
			{Name: "x-sucuri-id", Pattern: regexp.MustCompile(`.*`)},
			{Name: "x-sucuri-cache", Pattern: regexp.MustCompile(`.*`)},
			{Name: "server", Pattern: regexp.MustCompile(`(?i)sucuri`)},
		},
		DNSPatterns: []string{".sucuri.net", ".sucuridns.com"},
	},
	"google_cloud_cdn": {
		Name: "Google Cloud CDN",
		Type: "cdn",
		Headers: []HeaderSignature{
			{Name: "via", Pattern: regexp.MustCompile(`(?i)google`)},
			{Name: "server", Pattern: regexp.MustCompile(`(?i)^gws$|^gse$|^gfe`)},
			{Name: "x-goog-", Pattern: regexp.MustCompile(`.*`)},
		},
		DNSPatterns: []string{".googleusercontent.com", ".google.com", ".1e100.net"},
	},
	"stackpath": {
		Name: "StackPath",
		Type: "cdn",
		Headers: []HeaderSignature{
			{Name: "x-hw", Pattern: regexp.MustCompile(`.*`)},
			{Name: "server", Pattern: regexp.MustCompile(`(?i)stackpath|netdna|maxcdn`)},
		},
		DNSPatterns: []string{".stackpathdns.com", ".stackpathcdn.com"},
	},
	"keycdn": {
		Name: "KeyCDN",
		Type: "cdn",
		Headers: []HeaderSignature{
			{Name: "server", Pattern: regexp.MustCompile(`(?i)keycdn`)},
			{Name: "x-cache", Pattern: regexp.MustCompile(`(?i)keycdn`)},
		},
		DNSPatterns: []string{".kxcdn.com", ".keycdn.com"},
	},
	"bunnycdn": {
		Name: "BunnyCDN",
		Type: "cdn",
		Headers: []HeaderSignature{
			{Name: "server", Pattern: regexp.MustCompile(`(?i)bunnycdn`)},
			{Name: "cdn-pullzone", Pattern: regexp.MustCompile(`.*`)},
			{Name: "cdn-uid", Pattern: regexp.MustCompile(`.*`)},
		},
		DNSPatterns: []string{".b-cdn.net", ".bunnycdn.com"},
	},
	"ddos_guard": {
		Name: "DDoS-Guard",
		Type: "waf",
		Headers: []HeaderSignature{
			{Name: "server", Pattern: regexp.MustCompile(`(?i)ddos-guard`)},
		},
		DNSPatterns: []string{".ddos-guard.net"},
	},
}

const wafCDNHTTPTimeout = 15 * time.Second

// ScanWAFCDN detects WAF/CDN protection for a domain
func ScanWAFCDN(ctx context.Context, domain string, includeHeaders bool) *WAFCDNResult {
	// Normalize domain
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	domain = strings.Split(domain, "/")[0]

	if domain == "" {
		return &WAFCDNResult{
			ScanCompleted: false,
			Error:         "Domain parameter required",
		}
	}

	result := &WAFCDNResult{
		ScanCompleted: true,
		Domain:        domain,
		Detection: WAFCDNDetection{
			Provider:         "none",
			ProviderName:     "None detected",
			Type:             "none",
			Confidence:       "none",
			DetectionMethods: []string{},
		},
		DNSInfo: DNSChainInfo{Scanned: false},
		Issues:  []WAFCDNIssue{},
	}

	// Step 1: DNS analysis
	dnsInfo := analyzeDNS(ctx, domain)
	result.DNSInfo = dnsInfo

	// Step 2: HTTP request to get headers
	headers, cookies, resolvedIP := fetchHTTPInfo(ctx, domain)
	if includeHeaders && headers != nil {
		result.Headers = headers
	}

	result.IPInfo = IPRangeInfo{IP: resolvedIP}

	// Step 3: Detection
	var detectedProviders []string
	var detectionMethods []string
	confidence := "none"

	// Detect by headers
	if headers != nil {
		for providerID, provider := range cdnProviders {
			if matchHeaders(headers, provider.Headers) {
				detectedProviders = append(detectedProviders, providerID)
				detectionMethods = append(detectionMethods, "headers")
				confidence = "high"
			}
		}
	}

	// Detect by cookies
	if cookies != nil {
		for providerID, provider := range cdnProviders {
			if matchCookies(cookies, provider.Cookies) {
				if !contains(detectedProviders, providerID) {
					detectedProviders = append(detectedProviders, providerID)
				}
				if !contains(detectionMethods, "cookies") {
					detectionMethods = append(detectionMethods, "cookies")
				}
				confidence = "high"
			}
		}
	}

	// Detect by DNS
	for providerID, provider := range cdnProviders {
		if matchDNS(dnsInfo.CNAMEChain, provider.DNSPatterns) {
			if !contains(detectedProviders, providerID) {
				detectedProviders = append(detectedProviders, providerID)
			}
			if !contains(detectionMethods, "dns") {
				detectionMethods = append(detectionMethods, "dns")
			}
			dnsInfo.ProviderHints = append(dnsInfo.ProviderHints, provider.Name)
			if confidence == "none" {
				confidence = "medium"
			}
		}
	}

	// Detect by IP range (for Cloudflare)
	if resolvedIP != "" {
		if isCloudflareIP(ctx, resolvedIP) {
			if !contains(detectedProviders, "cloudflare") {
				detectedProviders = append(detectedProviders, "cloudflare")
			}
			if !contains(detectionMethods, "ip_range") {
				detectionMethods = append(detectionMethods, "ip_range")
			}
			result.IPInfo.MatchedProvider = "cloudflare"
			if confidence == "none" {
				confidence = "medium"
			}
		}
	}

	// Build final detection result
	if len(detectedProviders) > 0 {
		primaryProvider := detectedProviders[0]
		provider := cdnProviders[primaryProvider]

		result.Detection = WAFCDNDetection{
			Provider:         primaryProvider,
			ProviderName:     provider.Name,
			Type:             provider.Type,
			Confidence:       confidence,
			DetectionMethods: detectionMethods,
		}
	}

	// Analyze security posture
	result.SecurityPosture = analyzeSecurityPosture(result.Detection, headers)

	// Generate issues
	result.Issues = generateWAFCDNIssues(result)

	// Calculate summary
	result.Summary = WAFCDNSummary{
		Protected:  result.SecurityPosture.ProtectedByWAF || result.SecurityPosture.ProtectedByCDN,
		Provider:   result.Detection.ProviderName,
		IssueCount: len(result.Issues),
	}

	for _, issue := range result.Issues {
		switch issue.Severity {
		case "critical":
			result.Summary.CriticalIssues++
		case "high":
			result.Summary.HighIssues++
		}
	}

	return result
}

func analyzeDNS(ctx context.Context, domain string) DNSChainInfo {
	info := DNSChainInfo{
		Scanned:    true,
		CNAMEChain: []string{},
		FinalIPs:   []string{},
	}

	// Follow CNAME chain
	currentDomain := domain
	visited := make(map[string]bool)

	for i := 0; i < 10; i++ { // Max 10 hops
		if visited[currentDomain] {
			break
		}
		visited[currentDomain] = true

		cname, err := net.LookupCNAME(currentDomain)
		if err != nil {
			break
		}

		cname = strings.TrimSuffix(cname, ".")
		if cname == currentDomain || cname == "" {
			break
		}

		info.CNAMEChain = append(info.CNAMEChain, cname)
		currentDomain = cname
	}

	// Resolve final IPs
	ips, err := net.LookupIP(domain)
	if err == nil {
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				info.FinalIPs = append(info.FinalIPs, ipv4.String())
			}
		}
	}

	return info
}

func fetchHTTPInfo(ctx context.Context, domain string) (map[string][]string, []*http.Cookie, string) {
	jar, _ := cookiejar.New(nil)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // We want to detect even with invalid certs
		},
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Timeout:   wafCDNHTTPTimeout,
		Jar:       jar,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Try HTTPS first
	url := "https://" + domain
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, ""
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		// Fall back to HTTP
		url = "http://" + domain
		req, _ = http.NewRequestWithContext(ctx, "GET", url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err = client.Do(req)
		if err != nil {
			return nil, nil, ""
		}
	}
	defer func() { _ = resp.Body.Close() }()

	// Consume body to get cookies
	_, _ = io.Copy(io.Discard, resp.Body)

	// Get resolved IP from connection
	resolvedIP := ""
	if resp.Request != nil && resp.Request.URL != nil {
		host := resp.Request.URL.Hostname()
		ips, err := net.LookupIP(host)
		if err == nil && len(ips) > 0 {
			if ipv4 := ips[0].To4(); ipv4 != nil {
				resolvedIP = ipv4.String()
			}
		}
	}

	return resp.Header, resp.Cookies(), resolvedIP
}

func matchHeaders(headers map[string][]string, signatures []HeaderSignature) bool {
	for _, sig := range signatures {
		for headerName, values := range headers {
			if strings.EqualFold(headerName, sig.Name) {
				for _, value := range values {
					if sig.Pattern.MatchString(value) {
						return true
					}
				}
			}
			// Also check for prefix match (e.g., x-goog- matches x-goog-component)
			if strings.HasSuffix(sig.Name, "-") && strings.HasPrefix(strings.ToLower(headerName), strings.ToLower(sig.Name)) {
				return true
			}
		}
	}
	return false
}

func matchCookies(cookies []*http.Cookie, patterns []string) bool {
	for _, cookie := range cookies {
		for _, pattern := range patterns {
			if strings.HasPrefix(cookie.Name, pattern) {
				return true
			}
		}
	}
	return false
}

func matchDNS(cnameChain []string, patterns []string) bool {
	for _, cname := range cnameChain {
		cnameLower := strings.ToLower(cname)
		for _, pattern := range patterns {
			if strings.Contains(cnameLower, pattern) {
				return true
			}
		}
	}
	return false
}

// Cloudflare IP ranges (cached in memory for performance)
var cloudflareIPRanges []string
var cloudflareIPRangesLoaded bool

func isCloudflareIP(ctx context.Context, ip string) bool {
	if !cloudflareIPRangesLoaded {
		loadCloudflareIPRanges(ctx)
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, cidr := range cloudflareIPRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

func loadCloudflareIPRanges(ctx context.Context) {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.cloudflare.com/ips-v4", nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(line, "/") {
			cloudflareIPRanges = append(cloudflareIPRanges, line)
		}
	}

	cloudflareIPRangesLoaded = true
}

func analyzeSecurityPosture(detection WAFCDNDetection, headers map[string][]string) WAFSecurityPosture {
	posture := WAFSecurityPosture{
		DDoSProtection: "none",
		SSLTermination: "unknown",
	}

	switch detection.Type {
	case "waf+cdn":
		posture.ProtectedByWAF = true
		posture.ProtectedByCDN = true
		posture.DDoSProtection = "advanced"
	case "waf":
		posture.ProtectedByWAF = true
		posture.DDoSProtection = "basic"
	case "cdn":
		posture.ProtectedByCDN = true
		posture.DDoSProtection = "basic"
	}

	// Check for caching headers
	if headers != nil {
		if _, ok := headers["Cf-Cache-Status"]; ok {
			posture.EdgeCaching = true
		}
		if _, ok := headers["X-Cache"]; ok {
			posture.EdgeCaching = true
		}
		if _, ok := headers["Age"]; ok {
			posture.EdgeCaching = true
		}

		// Check for bot protection indicators
		for name := range headers {
			nameLower := strings.ToLower(name)
			if strings.Contains(nameLower, "bot") || strings.Contains(nameLower, "captcha") {
				posture.BotProtection = true
				break
			}
		}

		// Check rate limiting headers
		if _, ok := headers["X-Ratelimit-Limit"]; ok {
			posture.RateLimiting = true
		}
		if _, ok := headers["Retry-After"]; ok {
			posture.RateLimiting = true
		}
	}

	// Determine SSL termination
	if detection.Provider != "none" {
		posture.SSLTermination = "edge"
	}

	return posture
}

func generateWAFCDNIssues(result *WAFCDNResult) []WAFCDNIssue {
	var issues []WAFCDNIssue

	// No WAF detected
	if !result.SecurityPosture.ProtectedByWAF && !result.SecurityPosture.ProtectedByCDN {
		issues = append(issues, WAFCDNIssue{
			Severity:       "high",
			Type:           "no_waf_detected",
			Message:        "No WAF or CDN protection detected for " + result.Domain,
			Recommendation: "Consider adding a WAF service (Cloudflare, AWS WAF, Akamai, etc.) to protect against common web attacks like SQL injection, XSS, and DDoS",
		})
	}

	// CDN without WAF
	if result.SecurityPosture.ProtectedByCDN && !result.SecurityPosture.ProtectedByWAF {
		issues = append(issues, WAFCDNIssue{
			Severity:       "medium",
			Type:           "cdn_without_waf",
			Message:        "CDN detected but no WAF rules appear to be active",
			Recommendation: "Enable WAF rules in your CDN configuration to protect against application-layer attacks",
		})
	}

	// No DDoS protection
	if result.SecurityPosture.DDoSProtection == "none" {
		issues = append(issues, WAFCDNIssue{
			Severity:       "medium",
			Type:           "no_ddos_protection",
			Message:        "No DDoS protection detected",
			Recommendation: "Consider using a CDN or DDoS protection service to mitigate volumetric attacks",
		})
	}

	// Origin potentially exposed (multiple IPs or direct A record without CNAME)
	if len(result.DNSInfo.CNAMEChain) == 0 && len(result.DNSInfo.FinalIPs) > 0 && result.Detection.Provider == "none" {
		issues = append(issues, WAFCDNIssue{
			Severity:       "medium",
			Type:           "origin_potentially_exposed",
			Message:        "Domain resolves directly to IP without CDN/WAF proxy",
			Recommendation: "If using a WAF/CDN, ensure DNS is properly configured to route through the protection service",
		})
	}

	// No caching detected with CDN
	if result.SecurityPosture.ProtectedByCDN && !result.SecurityPosture.EdgeCaching {
		issues = append(issues, WAFCDNIssue{
			Severity:       "low",
			Type:           "no_edge_caching",
			Message:        "CDN detected but edge caching does not appear to be active",
			Recommendation: "Configure caching rules to improve performance and reduce origin load",
		})
	}

	return issues
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetIPInfo fetches additional IP information from ipinfo.io
func GetIPInfo(ctx context.Context, ip string) *IPRangeInfo {
	info := &IPRangeInfo{IP: ip}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://ipinfo.io/%s/json", ip), nil)
	if err != nil {
		return info
	}

	resp, err := client.Do(req)
	if err != nil {
		return info
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return info
	}

	var data struct {
		ASN struct {
			ASN  string `json:"asn"`
			Name string `json:"name"`
		} `json:"asn"`
		Org string `json:"org"`
	}

	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &data); err == nil {
		if data.ASN.ASN != "" {
			info.ASN = data.ASN.ASN
			info.ASNOrg = data.ASN.Name
		} else if data.Org != "" {
			info.ASNOrg = data.Org
		}
	}

	return info
}
