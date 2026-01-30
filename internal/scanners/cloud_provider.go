package scanners

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/girste/mcp-cybersec-watchdog/internal/system"
)

// CloudProviderInfo contains information about the cloud environment
type CloudProviderInfo struct {
	Detected         bool                 `json:"detected"`
	Provider         string               `json:"provider"`
	Region           string               `json:"region,omitempty"`
	AvailabilityZone string               `json:"availability_zone,omitempty"`
	InstanceID       string               `json:"instance_id,omitempty"`
	InstanceType     string               `json:"instance_type,omitempty"`
	AccountID        string               `json:"account_id,omitempty"`
	SecurityGroups   []CloudSecurityGroup `json:"security_groups,omitempty"`
	VPC              string               `json:"vpc,omitempty"`
	PublicIP         string               `json:"public_ip,omitempty"`
	PrivateIP        string               `json:"private_ip,omitempty"`
	Issues           []CloudIssue         `json:"issues,omitempty"`
}

// CloudSecurityGroup represents a cloud security group/firewall rule
type CloudSecurityGroup struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	InboundRules  []SecurityRule `json:"inbound_rules,omitempty"`
	OutboundRules []SecurityRule `json:"outbound_rules,omitempty"`
}

// SecurityRule represents a single firewall rule
type SecurityRule struct {
	Protocol    string `json:"protocol"`
	FromPort    int    `json:"from_port"`
	ToPort      int    `json:"to_port"`
	Source      string `json:"source"`
	Description string `json:"description,omitempty"`
}

// CloudIssue represents a security issue found in cloud configuration
type CloudIssue struct {
	Severity       string `json:"severity"`
	Type           string `json:"type"`
	Message        string `json:"message"`
	Recommendation string `json:"recommendation"`
}

// Cloud metadata endpoints
const (
	awsMetadataURL    = "http://169.254.169.254/latest/meta-data/"
	awsIMDSv2TokenURL = "http://169.254.169.254/latest/api/token"
	gcpMetadataURL    = "http://metadata.google.internal/computeMetadata/v1/"
	azureMetadataURL  = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
	doMetadataURL     = "http://169.254.169.254/metadata/v1/"
	metadataTimeout   = 2 * time.Second
)

// DetectCloudProvider attempts to detect which cloud provider we're running on
func DetectCloudProvider(ctx context.Context) *CloudProviderInfo {
	info := &CloudProviderInfo{
		Detected: false,
		Provider: "none",
	}

	// Try each provider in sequence (short timeout)
	client := &http.Client{Timeout: metadataTimeout}

	// AWS detection (try IMDSv2 first, then v1)
	if awsInfo := detectAWS(ctx, client); awsInfo != nil {
		return awsInfo
	}

	// GCP detection
	if gcpInfo := detectGCP(ctx, client); gcpInfo != nil {
		return gcpInfo
	}

	// Azure detection
	if azureInfo := detectAzure(ctx, client); azureInfo != nil {
		return azureInfo
	}

	// DigitalOcean detection
	if doInfo := detectDigitalOcean(ctx, client); doInfo != nil {
		return doInfo
	}

	// Check for DMI/SMBIOS hints as fallback
	if provider := detectByDMI(); provider != "" {
		info.Detected = true
		info.Provider = provider
	}

	return info
}

func detectAWS(ctx context.Context, client *http.Client) *CloudProviderInfo {
	// Try IMDSv2 first (more secure)
	token := getAWSIMDSv2Token(ctx, client)

	// Fetch instance identity
	instanceID := fetchAWSMetadata(ctx, client, "instance-id", token)
	if instanceID == "" {
		return nil
	}

	info := &CloudProviderInfo{
		Detected:   true,
		Provider:   "aws",
		InstanceID: instanceID,
	}

	// Get additional metadata
	info.InstanceType = fetchAWSMetadata(ctx, client, "instance-type", token)
	info.Region = fetchAWSMetadata(ctx, client, "placement/region", token)
	info.AvailabilityZone = fetchAWSMetadata(ctx, client, "placement/availability-zone", token)
	info.PublicIP = fetchAWSMetadata(ctx, client, "public-ipv4", token)
	info.PrivateIP = fetchAWSMetadata(ctx, client, "local-ipv4", token)

	// Get security groups if possible
	sgNames := fetchAWSMetadata(ctx, client, "security-groups", token)
	if sgNames != "" {
		// Try to get detailed SG info via AWS CLI
		info.SecurityGroups = getAWSSecurityGroups(ctx, instanceID)
	}

	// Analyze for issues
	info.Issues = analyzeAWSSecurityGroups(info.SecurityGroups)

	return info
}

func getAWSIMDSv2Token(ctx context.Context, client *http.Client) string {
	req, err := http.NewRequestWithContext(ctx, "PUT", awsIMDSv2TokenURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return string(tokenBytes)
}

func fetchAWSMetadata(ctx context.Context, client *http.Client, path, token string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", awsMetadataURL+path, nil)
	if err != nil {
		return ""
	}

	if token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(body))
}

// getAWSSecurityGroups fetches security groups using AWS CLI
func getAWSSecurityGroups(ctx context.Context, instanceID string) []CloudSecurityGroup {
	if !system.CommandExists("aws") {
		return nil
	}

	// First get security group IDs for this instance
	result, err := system.RunCommand(ctx, system.TimeoutMedium,
		"aws", "ec2", "describe-instances",
		"--instance-ids", instanceID,
		"--query", "Reservations[0].Instances[0].SecurityGroups[*].[GroupId,GroupName]",
		"--output", "json")

	if err != nil || result == nil || !result.Success {
		return nil
	}

	var sgList [][]string
	if err := json.Unmarshal([]byte(result.Stdout), &sgList); err != nil {
		return nil
	}

	var groups []CloudSecurityGroup
	for _, sg := range sgList {
		if len(sg) < 2 {
			continue
		}
		group := CloudSecurityGroup{
			ID:   sg[0],
			Name: sg[1],
		}

		// Fetch detailed rules for this security group
		rulesResult, err := system.RunCommand(ctx, system.TimeoutMedium,
			"aws", "ec2", "describe-security-groups",
			"--group-ids", sg[0],
			"--query", "SecurityGroups[0]",
			"--output", "json")

		if err == nil && rulesResult != nil && rulesResult.Success {
			var sgDetail struct {
				Description   string `json:"Description"`
				IpPermissions []struct {
					IpProtocol string `json:"IpProtocol"`
					FromPort   int    `json:"FromPort"`
					ToPort     int    `json:"ToPort"`
					IpRanges   []struct {
						CidrIp      string `json:"CidrIp"`
						Description string `json:"Description"`
					} `json:"IpRanges"`
				} `json:"IpPermissions"`
				IpPermissionsEgress []struct {
					IpProtocol string `json:"IpProtocol"`
					FromPort   int    `json:"FromPort"`
					ToPort     int    `json:"ToPort"`
					IpRanges   []struct {
						CidrIp      string `json:"CidrIp"`
						Description string `json:"Description"`
					} `json:"IpRanges"`
				} `json:"IpPermissionsEgress"`
			}

			if err := json.Unmarshal([]byte(rulesResult.Stdout), &sgDetail); err == nil {
				group.Description = sgDetail.Description

				for _, perm := range sgDetail.IpPermissions {
					for _, ipRange := range perm.IpRanges {
						group.InboundRules = append(group.InboundRules, SecurityRule{
							Protocol:    perm.IpProtocol,
							FromPort:    perm.FromPort,
							ToPort:      perm.ToPort,
							Source:      ipRange.CidrIp,
							Description: ipRange.Description,
						})
					}
				}

				for _, perm := range sgDetail.IpPermissionsEgress {
					for _, ipRange := range perm.IpRanges {
						group.OutboundRules = append(group.OutboundRules, SecurityRule{
							Protocol:    perm.IpProtocol,
							FromPort:    perm.FromPort,
							ToPort:      perm.ToPort,
							Source:      ipRange.CidrIp,
							Description: ipRange.Description,
						})
					}
				}
			}
		}

		groups = append(groups, group)
	}

	return groups
}

func analyzeAWSSecurityGroups(groups []CloudSecurityGroup) []CloudIssue {
	var issues []CloudIssue

	sensitivePorts := map[int]string{
		22:    "SSH",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
		9200:  "Elasticsearch",
		2379:  "etcd",
	}

	for _, group := range groups {
		for _, rule := range group.InboundRules {
			// Check for 0.0.0.0/0 on sensitive ports
			if rule.Source == "0.0.0.0/0" || rule.Source == "::/0" {
				for port, service := range sensitivePorts {
					if rule.FromPort <= port && rule.ToPort >= port {
						issues = append(issues, CloudIssue{
							Severity:       "high",
							Type:           "sg_overly_permissive",
							Message:        service + " (port " + strconv.Itoa(port) + ") is open to the world in security group " + group.Name,
							Recommendation: "Restrict " + service + " access to specific IP ranges or use a bastion host",
						})
					}
				}

				// Check for all ports open
				if rule.FromPort == 0 && rule.ToPort == 65535 {
					issues = append(issues, CloudIssue{
						Severity:       "critical",
						Type:           "sg_all_ports_open",
						Message:        "Security group " + group.Name + " allows all ports from " + rule.Source,
						Recommendation: "Restrict to only required ports",
					})
				}
			}
		}
	}

	return issues
}

func detectGCP(ctx context.Context, client *http.Client) *CloudProviderInfo {
	req, err := http.NewRequestWithContext(ctx, "GET", gcpMetadataURL+"project/project-id", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	projectID, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	info := &CloudProviderInfo{
		Detected:  true,
		Provider:  "gcp",
		AccountID: strings.TrimSpace(string(projectID)),
	}

	// Get instance name
	info.InstanceID = fetchGCPMetadata(ctx, client, "instance/name")
	info.InstanceType = fetchGCPMetadata(ctx, client, "instance/machine-type")
	info.AvailabilityZone = fetchGCPMetadata(ctx, client, "instance/zone")

	// Extract region from zone (e.g., projects/123/zones/us-central1-a -> us-central1)
	if info.AvailabilityZone != "" {
		parts := strings.Split(info.AvailabilityZone, "/")
		zone := parts[len(parts)-1]
		if idx := strings.LastIndex(zone, "-"); idx > 0 {
			info.Region = zone[:idx]
		}
	}

	// Get network info
	info.PrivateIP = fetchGCPMetadata(ctx, client, "instance/network-interfaces/0/ip")
	info.PublicIP = fetchGCPMetadata(ctx, client, "instance/network-interfaces/0/access-configs/0/external-ip")

	return info
}

func fetchGCPMetadata(ctx context.Context, client *http.Client, path string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", gcpMetadataURL+path, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(body))
}

func detectAzure(ctx context.Context, client *http.Client) *CloudProviderInfo {
	req, err := http.NewRequestWithContext(ctx, "GET", azureMetadataURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var azureData struct {
		Compute struct {
			Location          string `json:"location"`
			Name              string `json:"name"`
			ResourceGroupName string `json:"resourceGroupName"`
			SubscriptionID    string `json:"subscriptionId"`
			VMSize            string `json:"vmSize"`
			Zone              string `json:"zone"`
		} `json:"compute"`
		Network struct {
			Interface []struct {
				IPv4 struct {
					IPAddress []struct {
						PrivateIPAddress string `json:"privateIpAddress"`
						PublicIPAddress  string `json:"publicIpAddress"`
					} `json:"ipAddress"`
				} `json:"ipv4"`
			} `json:"interface"`
		} `json:"network"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	if err := json.Unmarshal(body, &azureData); err != nil {
		return nil
	}

	info := &CloudProviderInfo{
		Detected:         true,
		Provider:         "azure",
		Region:           azureData.Compute.Location,
		InstanceID:       azureData.Compute.Name,
		InstanceType:     azureData.Compute.VMSize,
		AvailabilityZone: azureData.Compute.Zone,
		AccountID:        azureData.Compute.SubscriptionID,
	}

	if len(azureData.Network.Interface) > 0 && len(azureData.Network.Interface[0].IPv4.IPAddress) > 0 {
		info.PrivateIP = azureData.Network.Interface[0].IPv4.IPAddress[0].PrivateIPAddress
		info.PublicIP = azureData.Network.Interface[0].IPv4.IPAddress[0].PublicIPAddress
	}

	return info
}

func detectDigitalOcean(ctx context.Context, client *http.Client) *CloudProviderInfo {
	req, err := http.NewRequestWithContext(ctx, "GET", doMetadataURL+"id", nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	dropletID, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	info := &CloudProviderInfo{
		Detected:   true,
		Provider:   "digitalocean",
		InstanceID: strings.TrimSpace(string(dropletID)),
	}

	// Get additional metadata
	info.Region = fetchDOMetadata(ctx, client, "region")
	info.PrivateIP = fetchDOMetadata(ctx, client, "interfaces/private/0/ipv4/address")
	info.PublicIP = fetchDOMetadata(ctx, client, "interfaces/public/0/ipv4/address")

	return info
}

func fetchDOMetadata(ctx context.Context, client *http.Client, path string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", doMetadataURL+path, nil)
	if err != nil {
		return ""
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(body))
}

// detectByDMI checks DMI/SMBIOS for cloud provider hints
func detectByDMI() string {
	dmiPaths := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/board_vendor",
		"/sys/class/dmi/id/chassis_vendor",
	}

	cloudHints := map[string]string{
		"amazon":       "aws",
		"ec2":          "aws",
		"google":       "gcp",
		"microsoft":    "azure",
		"digitalocean": "digitalocean",
		"droplet":      "digitalocean",
		"hetzner":      "hetzner",
		"linode":       "linode",
		"vultr":        "vultr",
		"ovh":          "ovh",
	}

	for _, path := range dmiPaths {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		value := strings.ToLower(strings.TrimSpace(string(content)))
		for hint, provider := range cloudHints {
			if strings.Contains(value, hint) {
				return provider
			}
		}
	}

	return ""
}

// CompareCloudFirewallWithLocal compares cloud security group rules with local listening ports
func CompareCloudFirewallWithLocal(cloudInfo *CloudProviderInfo, localPorts map[int]bool) []CloudIssue {
	var issues []CloudIssue

	if cloudInfo == nil || !cloudInfo.Detected || len(cloudInfo.SecurityGroups) == 0 {
		return issues
	}

	// Build map of allowed inbound ports from security groups
	allowedPorts := make(map[int]string)
	for _, sg := range cloudInfo.SecurityGroups {
		for _, rule := range sg.InboundRules {
			if rule.Source == "0.0.0.0/0" || rule.Source == "::/0" {
				for port := rule.FromPort; port <= rule.ToPort; port++ {
					allowedPorts[port] = sg.Name
				}
			}
		}
	}

	// Check for ports allowed in SG but not listening locally (potential misconfiguration)
	for port, sgName := range allowedPorts {
		if !localPorts[port] && port != 0 {
			// Only warn for common service ports, not all ports
			if port == 22 || port == 80 || port == 443 || port == 3306 || port == 5432 {
				issues = append(issues, CloudIssue{
					Severity:       "low",
					Type:           "sg_unused_rule",
					Message:        "Port " + strconv.Itoa(port) + " is allowed in security group " + sgName + " but no service is listening",
					Recommendation: "Remove unused security group rules to reduce attack surface",
				})
			}
		}
	}

	// Check for locally listening ports that are exposed via security groups
	sensitivePorts := map[int]string{
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
		9200:  "Elasticsearch",
	}

	for port := range localPorts {
		if sgName, allowed := allowedPorts[port]; allowed {
			if service, sensitive := sensitivePorts[port]; sensitive {
				issues = append(issues, CloudIssue{
					Severity:       "high",
					Type:           "sensitive_port_exposed",
					Message:        service + " (port " + strconv.Itoa(port) + ") is listening and exposed to internet via " + sgName,
					Recommendation: "Restrict " + service + " to internal network or specific IP ranges",
				})
			}
		}
	}

	return issues
}
