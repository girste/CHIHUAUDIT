package alertcodes

import "testing"

func TestGetPrefix(t *testing.T) {
	tests := []struct {
		analyzer string
		want     string
	}{
		{"firewall", "FW"},
		{"ssh", "SSH"},
		{"services", "SVC"},
		{"users", "USR"},
		{"files", "FILE"},
		{"sysctl", "SYS"},
		{"docker", "DOCK"},
		{"cron", "CRON"},
		{"security", "SEC"},
		{"unknown", "UNK"},
	}

	for _, tt := range tests {
		t.Run(tt.analyzer, func(t *testing.T) {
			got := GetPrefix(tt.analyzer)
			if got != tt.want {
				t.Errorf("GetPrefix(%s) = %s; want %s", tt.analyzer, got, tt.want)
			}
		})
	}
}

