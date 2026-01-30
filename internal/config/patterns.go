package config

import "strings"

// PortPatterns contains common port classifications
type PortPatterns struct {
	RiskyDatabase map[int]string
	WebPorts      []int
	DevPorts      []int
}

// ProcessPatterns contains process name patterns for auto-discovery
type ProcessPatterns struct {
	WebServers       []string
	ContainerRuntime []string
	Databases        []string
}

// DefaultPortPatterns returns the default port classification
func DefaultPortPatterns() *PortPatterns {
	return &PortPatterns{
		RiskyDatabase: map[int]string{
			3306:  "MySQL",
			5432:  "PostgreSQL",
			6379:  "Redis",
			27017: "MongoDB",
			9200:  "Elasticsearch",
			5984:  "CouchDB",
			8086:  "InfluxDB",
		},
		WebPorts: []int{80, 443, 8080, 8443},
		DevPorts: []int{3000, 5000, 8000, 8080, 9000},
	}
}

// DefaultProcessPatterns returns the default process patterns
func DefaultProcessPatterns() *ProcessPatterns {
	return &ProcessPatterns{
		WebServers: []string{
			"nginx", "apache", "httpd", "apache2",
			"caddy", "traefik", "lighttpd", "haproxy",
			"envoy", "h2o", "openresty", "tengine",
		},
		ContainerRuntime: []string{
			"docker", "podman", "containerd", "lxd", "lxc",
		},
		Databases: []string{
			"mysqld", "postgres", "redis-server", "mongod",
			"mariadb", "postgresql",
		},
	}
}

// IsWebPort checks if a port is commonly used for web services
func (p *PortPatterns) IsWebPort(port int) bool {
	for _, wp := range p.WebPorts {
		if wp == port {
			return true
		}
	}
	return false
}

// GetRiskyService returns the service name if port is risky, empty string otherwise
func (p *PortPatterns) GetRiskyService(port int) (string, bool) {
	service, exists := p.RiskyDatabase[port]
	return service, exists
}

// MatchesPattern checks if a string matches any pattern in the list (case-insensitive substring)
func MatchesPattern(input string, patterns []string) bool {
	inputLower := strings.ToLower(input)
	for _, pattern := range patterns {
		if strings.Contains(inputLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// IsWebServerProcess checks if a process name matches web server patterns
func (p *ProcessPatterns) IsWebServerProcess(processName string) bool {
	return MatchesPattern(processName, p.WebServers)
}

// IsContainerRuntime checks if a process name matches container runtime patterns
func (p *ProcessPatterns) IsContainerRuntime(processName string) bool {
	return MatchesPattern(processName, p.ContainerRuntime)
}

// IsDatabaseProcess checks if a process name matches database patterns
func (p *ProcessPatterns) IsDatabaseProcess(processName string) bool {
	return MatchesPattern(processName, p.Databases)
}
