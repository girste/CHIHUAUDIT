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
		{"docker", "DOC"},
		{"fail2ban", "F2B"},
		{"updates", "UPD"},
		{"kernel", "KRN"},
		{"disk", "DSK"},
		{"mac", "MAC"},
		{"ssl", "SSL"},
		{"threats", "THR"},
		{"sudo", "SDO"},
		{"cron", "CRN"},
		{"permissions", "PRM"},
		{"processes", "PRC"},
		{"performance", "PER"},
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
