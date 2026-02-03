package config

import "testing"

func TestGetRiskyService(t *testing.T) {
	ports := DefaultPortPatterns()

	tests := []struct {
		port       int
		expectName string
		expectOk   bool
	}{
		{3306, "MySQL", true},
		{5432, "PostgreSQL", true},
		{6379, "Redis", true},
		{27017, "MongoDB", true},
		{9999, "", false},
	}

	for _, tt := range tests {
		got, ok := ports.GetRiskyService(tt.port)
		if got != tt.expectName || ok != tt.expectOk {
			t.Errorf("GetRiskyService(%d) = (%q, %v), want (%q, %v)", tt.port, got, ok, tt.expectName, tt.expectOk)
		}
	}
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		input   string
		patterns []string
		expect  bool
	}{
		{"nginx", []string{"nginx"}, true},
		{"nginx-worker", []string{"nginx"}, true},
		{"apache2", []string{"nginx"}, false},
		{"mysqld", []string{"mysql"}, true},
		{"NGINX", []string{"nginx"}, true},
	}

	for _, tt := range tests {
		got := MatchesPattern(tt.input, tt.patterns)
		if got != tt.expect {
			t.Errorf("MatchesPattern(%q, %v) = %v, want %v", tt.input, tt.patterns, got, tt.expect)
		}
	}
}

func TestIsWebServerProcess(t *testing.T) {
	procs := DefaultProcessPatterns()

	tests := []struct {
		name   string
		expect bool
	}{
		{"nginx", true},
		{"nginx: worker", true},
		{"apache2", true},
		{"httpd", true},
		{"caddy", true},
		{"mysql", false},
		{"postgres", false},
	}

	for _, tt := range tests {
		got := procs.IsWebServerProcess(tt.name)
		if got != tt.expect {
			t.Errorf("IsWebServerProcess(%q) = %v, want %v", tt.name, got, tt.expect)
		}
	}
}

func TestIsContainerRuntime(t *testing.T) {
	procs := DefaultProcessPatterns()

	tests := []struct {
		name   string
		expect bool
	}{
		{"dockerd", true},
		{"containerd", true},
		{"podman", true},
		{"nginx", false},
	}

	for _, tt := range tests {
		got := procs.IsContainerRuntime(tt.name)
		if got != tt.expect {
			t.Errorf("IsContainerRuntime(%q) = %v, want %v", tt.name, got, tt.expect)
		}
	}
}

func TestIsDatabaseProcess(t *testing.T) {
	procs := DefaultProcessPatterns()

	tests := []struct {
		name   string
		expect bool
	}{
		{"mysqld", true},
		{"postgres", true},
		{"mongod", true},
		{"redis-server", true},
		{"nginx", false},
		{"apache2", false},
	}

	for _, tt := range tests {
		got := procs.IsDatabaseProcess(tt.name)
		if got != tt.expect {
			t.Errorf("IsDatabaseProcess(%q) = %v, want %v", tt.name, got, tt.expect)
		}
	}
}
