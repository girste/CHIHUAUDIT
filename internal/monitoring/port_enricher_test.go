package monitoring

import (
	"context"
	"testing"
)

func TestNormalizeBindAddr(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Wildcard asterisk", "*", "0.0.0.0"},
		{"IPv4 wildcard", "0.0.0.0", "0.0.0.0"},
		{"IPv6 wildcard", "[::]", "::"},
		{"IPv6 localhost", "::1", "127.0.0.1"},
		{"IPv6 localhost bracketed", "[::1]", "127.0.0.1"},
		{"IPv4 localhost", "127.0.0.1", "127.0.0.1"},
		{"Localhost subnet", "127.0.53.1", "127.0.53.1"},
		{"Specific IP", "192.168.1.100", "192.168.1.100"},
		{"With whitespace", "  127.0.0.1  ", "127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeBindAddr(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeBindAddr(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDetermineRisk(t *testing.T) {
	tests := []struct {
		name     string
		bindAddr string
		expected string
	}{
		{"Wildcard IPv4", "0.0.0.0", "high"},
		{"Wildcard IPv6", "::", "high"},
		{"Localhost", "127.0.0.1", "low"},
		{"Localhost IPv6", "::1", "low"},
		{"Localhost subnet", "127.0.53.1", "low"},
		{"Specific IP", "192.168.1.100", "medium"},
		{"Public IP", "8.8.8.8", "medium"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineRisk(tt.bindAddr)
			if result != tt.expected {
				t.Errorf("determineRisk(%q) = %q, want %q", tt.bindAddr, result, tt.expected)
			}
		})
	}
}

func TestFormatBindAddress(t *testing.T) {
	tests := []struct {
		name     string
		bind     string
		risk     string
		expected string
	}{
		{"Localhost low risk", "127.0.0.1", "low", "localhost ✓"},
		{"Wildcard high risk", "0.0.0.0", "high", "0.0.0.0 ⚠️ EXPOSED"},
		{"IPv6 wildcard high risk", "::", "high", ":: ⚠️ EXPOSED"},
		{"Specific IP medium risk", "192.168.1.1", "medium", "192.168.1.1"},
		{"Specific IP high risk", "192.168.1.1", "high", "192.168.1.1 ⚠️"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatBindAddress(tt.bind, tt.risk)
			if result != tt.expected {
				t.Errorf("formatBindAddress(%q, %q) = %q, want %q", tt.bind, tt.risk, result, tt.expected)
			}
		})
	}
}

func TestFormatEnrichedMessage(t *testing.T) {
	tests := []struct {
		name     string
		details  []PortDetail
		expected string
	}{
		{
			name:     "Empty details",
			details:  []PortDetail{},
			expected: "New services listening (details unavailable)",
		},
		{
			name: "Single port with full info",
			details: []PortDetail{
				{Port: 8080, Process: "nginx", PID: 1234, Bind: "127.0.0.1", Risk: "low"},
			},
			expected: "Port 8080: nginx/1234 (localhost ✓)",
		},
		{
			name: "Port with process but no PID",
			details: []PortDetail{
				{Port: 3000, Process: "node", PID: 0, Bind: "127.0.0.1", Risk: "low"},
			},
			expected: "Port 3000: node (localhost ✓)",
		},
		{
			name: "Port with unknown process",
			details: []PortDetail{
				{Port: 5432, Process: "unknown", PID: 0, Bind: "0.0.0.0", Risk: "high"},
			},
			expected: "Port 5432 (0.0.0.0 ⚠️ EXPOSED)",
		},
		{
			name: "Multiple ports",
			details: []PortDetail{
				{Port: 8080, Process: "nginx", PID: 1234, Bind: "127.0.0.1", Risk: "low"},
				{Port: 3306, Process: "mysqld", PID: 5678, Bind: "0.0.0.0", Risk: "high"},
			},
			expected: "Port 8080: nginx/1234 (localhost ✓) - Port 3306: mysqld/5678 (0.0.0.0 ⚠️ EXPOSED)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatEnrichedMessage(tt.details)
			if result != tt.expected {
				t.Errorf("FormatEnrichedMessage() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestContains(t *testing.T) {
	slice := []int{80, 443, 8080, 3306}

	tests := []struct {
		name     string
		item     int
		expected bool
	}{
		{"Contains first", 80, true},
		{"Contains middle", 8080, true},
		{"Contains last", 3306, true},
		{"Not contains", 22, false},
		{"Not contains zero", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(slice, tt.item)
			if result != tt.expected {
				t.Errorf("contains(%v, %d) = %v, want %v", slice, tt.item, result, tt.expected)
			}
		})
	}
}

func TestCreateBasicDetails(t *testing.T) {
	ports := []int{80, 443, 8080}
	details := createBasicDetails(ports)

	if len(details) != len(ports) {
		t.Fatalf("Expected %d details, got %d", len(ports), len(details))
	}

	for i, detail := range details {
		if detail.Port != ports[i] {
			t.Errorf("Detail %d: port = %d, want %d", i, detail.Port, ports[i])
		}
		if detail.Process != "unknown" {
			t.Errorf("Detail %d: process = %q, want %q", i, detail.Process, "unknown")
		}
		if detail.PID != 0 {
			t.Errorf("Detail %d: PID = %d, want 0", i, detail.PID)
		}
		if detail.Bind != "unknown" {
			t.Errorf("Detail %d: bind = %q, want %q", i, detail.Bind, "unknown")
		}
		if detail.Risk != "medium" {
			t.Errorf("Detail %d: risk = %q, want %q", i, detail.Risk, "medium")
		}
	}
}

func TestBuildOrderedResults(t *testing.T) {
	ports := []int{80, 443, 8080}
	portMap := map[int]PortDetail{
		80:   {Port: 80, Process: "nginx", PID: 1234, Bind: "0.0.0.0", Risk: "high"},
		8080: {Port: 8080, Process: "node", PID: 5678, Bind: "127.0.0.1", Risk: "low"},
		// 443 missing - should get default
	}

	results := buildOrderedResults(ports, portMap)

	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	// Check port 80 (found in map)
	if results[0].Port != 80 || results[0].Process != "nginx" || results[0].PID != 1234 {
		t.Errorf("Port 80: got %+v, want nginx/1234", results[0])
	}

	// Check port 443 (missing in map, should be default)
	if results[1].Port != 443 || results[1].Process != "unknown" {
		t.Errorf("Port 443: got %+v, want unknown process", results[1])
	}

	// Check port 8080 (found in map)
	if results[2].Port != 8080 || results[2].Process != "node" || results[2].PID != 5678 {
		t.Errorf("Port 8080: got %+v, want node/5678", results[2])
	}
}

func TestBuildPortPattern(t *testing.T) {
	tests := []struct {
		name     string
		ports    []int
		expected string
	}{
		{"Single port", []int{80}, ":(80)"},
		{"Two ports", []int{80, 443}, ":(80|443)"},
		{"Multiple ports", []int{22, 80, 443, 3306}, ":(22|80|443|3306)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildPortPattern(tt.ports)
			if result != tt.expected {
				t.Errorf("buildPortPattern(%v) = %q, want %q", tt.ports, result, tt.expected)
			}
		})
	}
}

// TestSSRegexParsing tests the regex patterns used to parse ss output
func TestSSRegexParsing(t *testing.T) {
	testLines := []struct {
		name            string
		line            string
		expectedAddr    string
		expectedPort    string
		expectedProcess string
		expectedPID     string
		shouldMatch     bool
	}{
		{
			name:            "IPv4 localhost with process",
			line:            `LISTEN 0      511        127.0.0.1:26959       0.0.0.0:*    users:(("node",pid=1906546,fd=48))`,
			expectedAddr:    "127.0.0.1",
			expectedPort:    "26959",
			expectedProcess: "node",
			expectedPID:     "1906546",
			shouldMatch:     true,
		},
		{
			name:            "IPv4 wildcard with process",
			line:            `LISTEN 0      80         0.0.0.0:80            0.0.0.0:*    users:(("nginx",pid=1234,fd=6))`,
			expectedAddr:    "0.0.0.0",
			expectedPort:    "80",
			expectedProcess: "nginx",
			expectedPID:     "1234",
			shouldMatch:     true,
		},
		{
			name:            "IPv6 localhost",
			line:            `LISTEN 0      128        [::1]:8080            [::]:*       users:(("java",pid=999,fd=10))`,
			expectedAddr:    "[::1]",
			expectedPort:    "8080",
			expectedProcess: "java",
			expectedPID:     "999",
			shouldMatch:     true,
		},
		{
			name:            "Process with dash in name",
			line:            `LISTEN 0      128        127.0.0.1:5432        0.0.0.0:*    users:(("postgres-main",pid=5000,fd=5))`,
			expectedAddr:    "127.0.0.1",
			expectedPort:    "5432",
			expectedProcess: "postgres-main",
			expectedPID:     "5000",
			shouldMatch:     true,
		},
	}

	for _, tt := range testLines {
		t.Run(tt.name, func(t *testing.T) {
			// Test address regex
			addrMatches := ssAddrRegex.FindStringSubmatch(tt.line)
			if tt.shouldMatch && len(addrMatches) < 3 {
				t.Errorf("Address regex failed to match: %q", tt.line)
			}
			if tt.shouldMatch && len(addrMatches) >= 3 {
				if addrMatches[1] != tt.expectedAddr {
					t.Errorf("Address: got %q, want %q", addrMatches[1], tt.expectedAddr)
				}
				if addrMatches[2] != tt.expectedPort {
					t.Errorf("Port: got %q, want %q", addrMatches[2], tt.expectedPort)
				}
			}

			// Test process regex
			procMatches := ssProcRegex.FindStringSubmatch(tt.line)
			if tt.shouldMatch && len(procMatches) < 3 {
				t.Errorf("Process regex failed to match: %q", tt.line)
			}
			if tt.shouldMatch && len(procMatches) >= 3 {
				if procMatches[1] != tt.expectedProcess {
					t.Errorf("Process: got %q, want %q", procMatches[1], tt.expectedProcess)
				}
				if procMatches[2] != tt.expectedPID {
					t.Errorf("PID: got %q, want %q", procMatches[2], tt.expectedPID)
				}
			}
		})
	}
}

// TestEnrichPortDetailsEmpty tests edge case with empty port list
func TestEnrichPortDetailsEmpty(t *testing.T) {
	ctx := context.Background()
	details := EnrichPortDetails(ctx, []int{})

	if len(details) != 0 {
		t.Errorf("Expected empty details for empty ports, got %d items", len(details))
	}
}

// TestEnrichPortDetailsNoTools tests fallback when neither ss nor netstat is available
// This is a conceptual test - in real scenarios we'd mock CommandExists
func TestEnrichPortDetailsNoTools(t *testing.T) {
	// When neither ss nor netstat exists, createBasicDetails should be called
	ports := []int{80, 443}
	basic := createBasicDetails(ports)

	if len(basic) != 2 {
		t.Errorf("Expected 2 basic details, got %d", len(basic))
	}

	for i, detail := range basic {
		if detail.Port != ports[i] {
			t.Errorf("Port mismatch: got %d, want %d", detail.Port, ports[i])
		}
		if detail.Process != "unknown" {
			t.Errorf("Expected unknown process, got %q", detail.Process)
		}
	}
}
