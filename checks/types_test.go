package checks

import (
	"testing"
	"time"
)

func TestAuditResultsStructure(t *testing.T) {
	results := &AuditResults{
		Timestamp: time.Now(),
		Hostname:  "test",
		OS:        "Ubuntu",
		Kernel:    "6.5.0",
		Uptime:    "1h",
	}

	if results.Hostname != "test" {
		t.Errorf("Hostname = %q, want %q", results.Hostname, "test")
	}
	if results.OS != "Ubuntu" {
		t.Errorf("OS = %q, want %q", results.OS, "Ubuntu")
	}
}

func TestSecurityStructure(t *testing.T) {
	sec := Security{
		Firewall:      "ufw",
		FirewallRules: 10,
		SSHStatus:     "active",
		SSHPort:       22,
		OpenPorts:     []int{22, 80, 443},
	}

	if sec.Firewall != "ufw" {
		t.Errorf("Firewall = %q, want %q", sec.Firewall, "ufw")
	}
	if sec.FirewallRules != 10 {
		t.Errorf("FirewallRules = %d, want %d", sec.FirewallRules, 10)
	}
	if len(sec.OpenPorts) != 3 {
		t.Errorf("OpenPorts length = %d, want 3", len(sec.OpenPorts))
	}
}

func TestServicesStructure(t *testing.T) {
	svc := Services{
		TotalRunning: 14,
		Failed:       1,
		WebStatus:    "nginx: active",
		DBStatus:     "postgres: active",
	}

	if svc.TotalRunning != 14 {
		t.Errorf("TotalRunning = %d, want 14", svc.TotalRunning)
	}
	if svc.Failed != 1 {
		t.Errorf("Failed = %d, want 1", svc.Failed)
	}
}

func TestResourcesStructure(t *testing.T) {
	res := Resources{
		CPUPercent: 45.5,
		MemPercent: 60.2,
		CPULoad1:   1.5,
		CPULoad5:   1.2,
		CPULoad15:  1.0,
		DiskMounts: []DiskMount{
			{Path: "/", Used: 50000000000, Total: 100000000000, Percent: 50.0},
			{Path: "/home", Used: 20000000000, Total: 50000000000, Percent: 40.0},
		},
	}

	if res.CPUPercent != 45.5 {
		t.Errorf("CPUPercent = %v, want 45.5", res.CPUPercent)
	}
	if len(res.DiskMounts) != 2 {
		t.Errorf("DiskMounts length = %d, want 2", len(res.DiskMounts))
	}
	if res.DiskMounts[0].Path != "/" {
		t.Errorf("DiskMounts[0].Path = %q, want %q", res.DiskMounts[0].Path, "/")
	}
}

func TestDiskMountStructure(t *testing.T) {
	mount := DiskMount{
		Path:    "/data",
		Used:    100000000000,
		Total:   500000000000,
		Percent: 20.0,
	}

	if mount.Path != "/data" {
		t.Errorf("Path = %q, want %q", mount.Path, "/data")
	}
	if mount.Percent != 20.0 {
		t.Errorf("Percent = %v, want 20.0", mount.Percent)
	}
}

func TestStorageStructure(t *testing.T) {
	storage := Storage{
		DiskHealth: "all PASSED",
		IOWait:     0.5,
	}

	if storage.DiskHealth != "all PASSED" {
		t.Errorf("DiskHealth = %q, want %q", storage.DiskHealth, "all PASSED")
	}
	if storage.IOWait != 0.5 {
		t.Errorf("IOWait = %v, want 0.5", storage.IOWait)
	}
}

func TestDatabaseStructure(t *testing.T) {
	db := Database{
		PostgreSQL: PostgreSQLInfo{
			Available:   true,
			Connections: 10,
		},
		MySQL: MySQLInfo{
			Available:   false,
			Connections: 0,
		},
		Redis: RedisInfo{
			Available: true,
			Memory:    "128M",
		},
	}

	if !db.PostgreSQL.Available {
		t.Error("PostgreSQL.Available should be true")
	}
	if db.PostgreSQL.Connections != 10 {
		t.Errorf("PostgreSQL.Connections = %d, want 10", db.PostgreSQL.Connections)
	}
}

func TestDockerStructure(t *testing.T) {
	docker := Docker{
		Available: true,
		Running:   5,
		Stopped:   2,
		Images:    10,
	}

	if !docker.Available {
		t.Error("Available should be true")
	}
	if docker.Running != 5 {
		t.Errorf("Running = %d, want 5", docker.Running)
	}
}

func TestSystemStructure(t *testing.T) {
	sys := System{
		ListeningPorts: 5,
		ActiveConns:    150,
		CronJobs:       10,
		NTPSync:        true,
	}

	if sys.ListeningPorts != 5 {
		t.Errorf("ListeningPorts = %d, want 5", sys.ListeningPorts)
	}
	if sys.ActiveConns != 150 {
		t.Errorf("ActiveConns = %d, want 150", sys.ActiveConns)
	}
}

func TestLogsStructure(t *testing.T) {
	logs := Logs{
		SyslogErrors: 25,
		SSHFailed:    5,
		ServiceRestarts: []ServiceRestart{
			{Service: "nginx", Count: 2},
			{Service: "postgres", Count: 1},
		},
	}

	if logs.SyslogErrors != 25 {
		t.Errorf("SyslogErrors = %d, want 25", logs.SyslogErrors)
	}
	if len(logs.ServiceRestarts) != 2 {
		t.Errorf("ServiceRestarts length = %d, want 2", len(logs.ServiceRestarts))
	}
}

func TestNetworkStructure(t *testing.T) {
	net := Network{
		DNSResolution: "ok",
		PingLatency:   "15ms",
		TopIPs: []IPConnection{
			{IP: "192.168.1.1", Count: 10},
			{IP: "8.8.8.8", Count: 5},
		},
	}

	if net.DNSResolution != "ok" {
		t.Errorf("DNSResolution = %q, want %q", net.DNSResolution, "ok")
	}
	if len(net.TopIPs) != 2 {
		t.Errorf("TopIPs length = %d, want 2", len(net.TopIPs))
	}
}

func TestBackupsStructure(t *testing.T) {
	backup := Backups{
		LastBackup:  "2024-02-05",
		BackupDir:   "/backups",
		DirExists:   true,
		RecentFiles: []string{"backup1.tar.gz", "backup2.tar.gz"},
	}

	if backup.LastBackup != "2024-02-05" {
		t.Errorf("LastBackup = %q, want %q", backup.LastBackup, "2024-02-05")
	}
	if len(backup.RecentFiles) != 2 {
		t.Errorf("RecentFiles = %d, want 2", len(backup.RecentFiles))
	}
}
