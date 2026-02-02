package scanners

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/girste/chihuaudit/internal/system"
)

// DatabaseSecurityResult is the result of a database security scan
type DatabaseSecurityResult struct {
	ScanCompleted  bool               `json:"scan_completed"`
	DatabaseType   string             `json:"db_type"`
	DatabasesFound []string           `json:"databases_found"`
	DatabasesCount int                `json:"databases_count"`
	Databases      []DatabaseScanInfo `json:"databases,omitempty"`
	Issues         []DatabaseIssue    `json:"issues"`
	Summary        DatabaseSummary    `json:"summary"`
	Error          string             `json:"error,omitempty"`
}

type DatabaseScanInfo struct {
	Type    string                 `json:"type"`
	Running bool                   `json:"running"`
	Port    int                    `json:"port,omitempty"`
	Binding string                 `json:"binding,omitempty"`
	Version string                 `json:"version,omitempty"`
	Issues  []DatabaseIssue        `json:"issues,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

type DatabaseIssue struct {
	Severity       string `json:"severity"`
	Type           string `json:"type"`
	Database       string `json:"database"`
	Message        string `json:"message"`
	Recommendation string `json:"recommendation"`
}

type DatabaseSummary struct {
	TotalIssues int `json:"total_issues"`
	Critical    int `json:"critical"`
	High        int `json:"high"`
	Medium      int `json:"medium"`
}

// Database detection info
type dbInfo struct {
	name        string
	serviceName string
	defaultPort int
	configPaths []string
	checkCmd    []string
}

var databaseTypes = map[string]dbInfo{
	"mysql": {
		name:        "MySQL/MariaDB",
		serviceName: "mysql",
		defaultPort: 3306,
		configPaths: []string{"/etc/mysql/my.cnf", "/etc/my.cnf", "/etc/mysql/mysql.conf.d/mysqld.cnf"},
		checkCmd:    []string{"mysqld", "--version"},
	},
	"postgresql": {
		name:        "PostgreSQL",
		serviceName: "postgresql",
		defaultPort: 5432,
		configPaths: []string{"/etc/postgresql/*/main/postgresql.conf", "/var/lib/pgsql/data/postgresql.conf"},
		checkCmd:    []string{"postgres", "--version"},
	},
	"mongodb": {
		name:        "MongoDB",
		serviceName: "mongod",
		defaultPort: 27017,
		configPaths: []string{"/etc/mongod.conf", "/etc/mongodb.conf"},
		checkCmd:    []string{"mongod", "--version"},
	},
	"redis": {
		name:        "Redis",
		serviceName: "redis",
		defaultPort: 6379,
		configPaths: []string{"/etc/redis/redis.conf", "/etc/redis.conf"},
		checkCmd:    []string{"redis-server", "--version"},
	},
}

// ScanDatabaseSecurity audits database security configurations
func ScanDatabaseSecurity(ctx context.Context, dbType string) *DatabaseSecurityResult {
	if dbType != "auto" && dbType != "mysql" && dbType != "postgresql" && dbType != "mongodb" && dbType != "redis" {
		return &DatabaseSecurityResult{
			ScanCompleted: false,
			Error:         "Invalid db_type. Use: auto, mysql, postgresql, mongodb, redis",
		}
	}

	result := &DatabaseSecurityResult{
		ScanCompleted:  true,
		DatabaseType:   dbType,
		DatabasesFound: []string{},
		Issues:         []DatabaseIssue{},
	}

	var typesToScan []string
	if dbType == "auto" {
		typesToScan = []string{"mysql", "postgresql", "mongodb", "redis"}
	} else {
		typesToScan = []string{dbType}
	}

	for _, dt := range typesToScan {
		info := databaseTypes[dt]

		// Check if running
		running := system.IsServiceActive(ctx, info.serviceName)
		if !running {
			// Try alternative service names
			altNames := map[string][]string{
				"mysql":      {"mariadb", "mysqld"},
				"postgresql": {"postgres", "postgresql@*"},
				"mongodb":    {"mongodb"},
				"redis":      {"redis-server"},
			}
			for _, alt := range altNames[dt] {
				if system.IsServiceActive(ctx, alt) {
					running = true
					break
				}
			}
		}

		if !running {
			continue
		}

		result.DatabasesFound = append(result.DatabasesFound, dt)

		dbScan := DatabaseScanInfo{
			Type:    dt,
			Running: true,
			Port:    info.defaultPort,
			Details: make(map[string]interface{}),
		}

		// Get version
		vResult, _ := system.RunCommand(ctx, system.TimeoutShort, info.checkCmd...)
		if vResult != nil && vResult.Success {
			dbScan.Version = strings.TrimSpace(vResult.Stdout)
		}

		// Scan specific database
		var issues []DatabaseIssue
		switch dt {
		case "mysql":
			issues, dbScan.Details = scanMySQL(ctx, info)
		case "postgresql":
			issues, dbScan.Details = scanPostgreSQL(ctx, info)
		case "mongodb":
			issues, dbScan.Details = scanMongoDB(ctx, info)
		case "redis":
			issues, dbScan.Details = scanRedis(ctx, info)
		}

		dbScan.Issues = issues
		result.Issues = append(result.Issues, issues...)
		result.Databases = append(result.Databases, dbScan)
	}

	result.DatabasesCount = len(result.DatabasesFound)

	// Calculate summary
	for _, issue := range result.Issues {
		switch issue.Severity {
		case "critical":
			result.Summary.Critical++
		case "high":
			result.Summary.High++
		case "medium":
			result.Summary.Medium++
		}
	}
	result.Summary.TotalIssues = len(result.Issues)

	if len(result.DatabasesFound) == 0 {
		result.Error = "No running databases detected"
	}

	return result
}

func scanMySQL(ctx context.Context, info dbInfo) ([]DatabaseIssue, map[string]interface{}) {
	var issues []DatabaseIssue
	details := make(map[string]interface{})

	// Find and read config
	for _, pattern := range info.configPaths {
		matches, _ := filepath.Glob(pattern)
		for _, configPath := range matches {
			content, err := os.ReadFile(configPath)
			if err != nil {
				// Try with sudo
				result, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "cat", configPath)
				if result != nil && result.Success {
					content = []byte(result.Stdout)
				} else {
					continue
				}
			}

			configStr := string(content)
			details["config_path"] = configPath

			// Check bind-address
			bindMatch := regexp.MustCompile(`(?m)^\s*bind-address\s*=\s*(.+)`).FindStringSubmatch(configStr)
			if len(bindMatch) > 1 {
				bindAddr := strings.TrimSpace(bindMatch[1])
				details["bind_address"] = bindAddr
				if bindAddr == "0.0.0.0" || bindAddr == "*" {
					issues = append(issues, DatabaseIssue{
						Severity:       "high",
						Type:           "remote_access",
						Database:       "mysql",
						Message:        "MySQL is bound to all interfaces (0.0.0.0)",
						Recommendation: "Bind to 127.0.0.1 unless remote access is required",
					})
				}
			}

			// Check skip-grant-tables
			if strings.Contains(configStr, "skip-grant-tables") {
				issues = append(issues, DatabaseIssue{
					Severity:       "critical",
					Type:           "auth_disabled",
					Database:       "mysql",
					Message:        "skip-grant-tables is enabled - authentication bypassed",
					Recommendation: "Remove skip-grant-tables from configuration immediately",
				})
			}

			break
		}
	}

	// Check for empty root password
	result, _ := system.RunCommand(ctx, system.TimeoutShort, "mysql", "-u", "root", "-e", "SELECT 1")
	if result != nil && result.Success {
		issues = append(issues, DatabaseIssue{
			Severity:       "critical",
			Type:           "weak_password",
			Database:       "mysql",
			Message:        "MySQL root user has no password",
			Recommendation: "Set a strong password for root: ALTER USER 'root'@'localhost' IDENTIFIED BY 'password'",
		})
		details["root_no_password"] = true
	}

	return issues, details
}

func scanPostgreSQL(ctx context.Context, info dbInfo) ([]DatabaseIssue, map[string]interface{}) {
	var issues []DatabaseIssue
	details := make(map[string]interface{})

	// Find config files
	configPaths := []string{}
	for _, pattern := range info.configPaths {
		matches, _ := filepath.Glob(pattern)
		configPaths = append(configPaths, matches...)
	}

	for _, configPath := range configPaths {
		content, err := os.ReadFile(configPath)
		if err != nil {
			result, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "cat", configPath)
			if result != nil && result.Success {
				content = []byte(result.Stdout)
			} else {
				continue
			}
		}

		configStr := string(content)
		details["config_path"] = configPath

		// Check listen_addresses
		listenMatch := regexp.MustCompile(`(?m)^\s*listen_addresses\s*=\s*'([^']+)'`).FindStringSubmatch(configStr)
		if len(listenMatch) > 1 {
			listenAddr := listenMatch[1]
			details["listen_addresses"] = listenAddr
			if listenAddr == "*" || listenAddr == "0.0.0.0" {
				issues = append(issues, DatabaseIssue{
					Severity:       "high",
					Type:           "remote_access",
					Database:       "postgresql",
					Message:        "PostgreSQL is listening on all interfaces",
					Recommendation: "Set listen_addresses = 'localhost' unless remote access is required",
				})
			}
		}

		break
	}

	// Check pg_hba.conf for trust authentication
	hbaPattern := regexp.MustCompile(`/etc/postgresql/\d+/main`)
	for _, configPath := range configPaths {
		if hbaPattern.MatchString(configPath) {
			hbaPath := filepath.Join(filepath.Dir(configPath), "pg_hba.conf")
			content, err := os.ReadFile(hbaPath)
			if err != nil {
				result, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "cat", hbaPath)
				if result != nil && result.Success {
					content = []byte(result.Stdout)
				}
			}

			if len(content) > 0 {
				lines := strings.Split(string(content), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") || line == "" {
						continue
					}
					if strings.Contains(line, "trust") && !strings.Contains(line, "local") {
						issues = append(issues, DatabaseIssue{
							Severity:       "critical",
							Type:           "weak_auth",
							Database:       "postgresql",
							Message:        "Trust authentication used for non-local connections",
							Recommendation: "Use md5 or scram-sha-256 authentication in pg_hba.conf",
						})
						break
					}
				}
			}
			break
		}
	}

	return issues, details
}

func scanMongoDB(ctx context.Context, info dbInfo) ([]DatabaseIssue, map[string]interface{}) {
	var issues []DatabaseIssue
	details := make(map[string]interface{})

	for _, configPath := range info.configPaths {
		content, err := os.ReadFile(configPath)
		if err != nil {
			result, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "cat", configPath)
			if result != nil && result.Success {
				content = []byte(result.Stdout)
			} else {
				continue
			}
		}

		configStr := string(content)
		details["config_path"] = configPath

		// Check bindIp
		if strings.Contains(configStr, "bindIp: 0.0.0.0") || strings.Contains(configStr, "bindIpAll: true") {
			issues = append(issues, DatabaseIssue{
				Severity:       "high",
				Type:           "remote_access",
				Database:       "mongodb",
				Message:        "MongoDB is bound to all interfaces",
				Recommendation: "Set bindIp: 127.0.0.1 unless remote access is required",
			})
			details["bind_all"] = true
		}

		// Check authorization
		if !strings.Contains(configStr, "authorization: enabled") {
			issues = append(issues, DatabaseIssue{
				Severity:       "critical",
				Type:           "auth_disabled",
				Database:       "mongodb",
				Message:        "MongoDB authorization is not enabled",
				Recommendation: "Enable authorization in mongod.conf: security.authorization: enabled",
			})
			details["auth_disabled"] = true
		}

		break
	}

	// Try to connect without auth
	result, _ := system.RunCommand(ctx, system.TimeoutShort, "mongosh", "--eval", "db.stats()", "--quiet")
	if result != nil && result.Success && !strings.Contains(result.Stderr, "requires authentication") {
		issues = append(issues, DatabaseIssue{
			Severity:       "critical",
			Type:           "no_auth",
			Database:       "mongodb",
			Message:        "MongoDB accepts connections without authentication",
			Recommendation: "Enable authentication and create admin user",
		})
	}

	return issues, details
}

func scanRedis(ctx context.Context, info dbInfo) ([]DatabaseIssue, map[string]interface{}) {
	var issues []DatabaseIssue
	details := make(map[string]interface{})

	for _, configPath := range info.configPaths {
		content, err := os.ReadFile(configPath)
		if err != nil {
			result, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "cat", configPath)
			if result != nil && result.Success {
				content = []byte(result.Stdout)
			} else {
				continue
			}
		}

		configStr := string(content)
		details["config_path"] = configPath

		// Check bind address
		bindMatch := regexp.MustCompile(`(?m)^\s*bind\s+(.+)`).FindStringSubmatch(configStr)
		if len(bindMatch) > 1 {
			bindAddr := strings.TrimSpace(bindMatch[1])
			details["bind"] = bindAddr
			if strings.Contains(bindAddr, "0.0.0.0") {
				issues = append(issues, DatabaseIssue{
					Severity:       "high",
					Type:           "remote_access",
					Database:       "redis",
					Message:        "Redis is bound to all interfaces",
					Recommendation: "Bind to 127.0.0.1 only unless remote access is required",
				})
			}
		}

		// Check protected-mode
		if strings.Contains(configStr, "protected-mode no") {
			issues = append(issues, DatabaseIssue{
				Severity:       "critical",
				Type:           "protection_disabled",
				Database:       "redis",
				Message:        "Redis protected-mode is disabled",
				Recommendation: "Enable protected-mode: protected-mode yes",
			})
		}

		// Check requirepass
		if !regexp.MustCompile(`(?m)^\s*requirepass\s+\S+`).MatchString(configStr) {
			issues = append(issues, DatabaseIssue{
				Severity:       "high",
				Type:           "no_password",
				Database:       "redis",
				Message:        "Redis has no password configured",
				Recommendation: "Set a strong password: requirepass yourpassword",
			})
		}

		// Check dangerous commands
		dangerousCmds := []string{"FLUSHALL", "FLUSHDB", "CONFIG", "DEBUG", "SHUTDOWN"}
		disabledCmds := regexp.MustCompile(`(?m)^\s*rename-command\s+(\w+)\s+""`).FindAllStringSubmatch(configStr, -1)
		disabledSet := make(map[string]bool)
		for _, m := range disabledCmds {
			if len(m) > 1 {
				disabledSet[strings.ToUpper(m[1])] = true
			}
		}

		for _, cmd := range dangerousCmds {
			if !disabledSet[cmd] {
				issues = append(issues, DatabaseIssue{
					Severity:       "medium",
					Type:           "dangerous_command",
					Database:       "redis",
					Message:        fmt.Sprintf("Dangerous command %s is not disabled", cmd),
					Recommendation: fmt.Sprintf("Disable with: rename-command %s \"\"", cmd),
				})
				break // Only report once
			}
		}

		break
	}

	return issues, details
}
