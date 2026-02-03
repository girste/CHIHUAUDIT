package monitoring

import (
	"context"
	"testing"

	"github.com/girste/chihuaudit/internal/config"
)

func TestCheckSystemHealth(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{}

	health := CheckSystemHealth(ctx, cfg)

	if health == nil {
		t.Fatal("CheckSystemHealth returned nil")
	}

	if len(health.LoadAverage) != 3 {
		t.Errorf("Expected 3 load average values, got %d", len(health.LoadAverage))
	}

	if health.UptimeSeconds < 0 {
		t.Error("UptimeSeconds should be non-negative")
	}

	if health.MemoryUsedPct < 0 || health.MemoryUsedPct > 100 {
		t.Errorf("Memory used percent out of range: %f", health.MemoryUsedPct)
	}

	if health.SwapUsedPct < 0 || health.SwapUsedPct > 100 {
		t.Errorf("Swap used percent out of range: %f", health.SwapUsedPct)
	}
}

func TestDetectSystemHealthAnomalies(t *testing.T) {
	tests := []struct {
		name   string
		health *SystemHealth
		want   int
	}{
		{
			name: "no anomalies",
			health: &SystemHealth{
				MemoryUsedPct: 50,
				SwapUsedPct:   5,
			},
			want: 0,
		},
		{
			name: "service down",
			health: &SystemHealth{
				ServicesDown: []ServiceStatus{
					{Name: "nginx", Active: false, Enabled: true},
				},
			},
			want: 1,
		},
		{
			name: "disk full",
			health: &SystemHealth{
				DiskCritical: []DiskStatus{
					{Mountpoint: "/", UsedPct: 95, Available: "5GB"},
				},
			},
			want: 1,
		},
		{
			name: "oom kills",
			health: &SystemHealth{
				OOMKills:      3,
				MemoryUsedPct: 95,
			},
			want: 1,
		},
		{
			name: "memory pressure without oom",
			health: &SystemHealth{
				MemoryPressure: true,
				MemoryUsedPct:  95,
				SwapUsedPct:    15,
			},
			want: 1,
		},
		{
			name: "failed services",
			health: &SystemHealth{
				FailedServices: []string{"service1.service", "service2.service"},
			},
			want: 1,
		},
		{
			name: "high journal errors",
			health: &SystemHealth{
				JournalErrors: 25,
			},
			want: 1,
		},
		{
			name: "multiple issues",
			health: &SystemHealth{
				ServicesDown: []ServiceStatus{
					{Name: "nginx", Active: false, Enabled: true},
				},
				DiskCritical: []DiskStatus{
					{Mountpoint: "/", UsedPct: 95},
				},
				OOMKills:       2,
				MemoryUsedPct:  95,
				JournalErrors:  20,
				FailedServices: []string{"test.service"},
			},
			want: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			anomalies := detectSystemHealthAnomalies(tt.health)
			if len(anomalies) != tt.want {
				t.Errorf("Expected %d anomalies, got %d", tt.want, len(anomalies))
			}

			// Verify anomaly structure
			for _, anom := range anomalies {
				if anom.Message == "" {
					t.Error("Anomaly message should not be empty")
				}
				if anom.Category == "" {
					t.Error("Anomaly category should not be empty")
				}
				if anom.Details == nil {
					t.Error("Anomaly details should not be nil")
				}
			}
		})
	}
}

func TestServiceStatus(t *testing.T) {
	svc := ServiceStatus{
		Name:    "nginx",
		Active:  true,
		Enabled: true,
		PID:     1234,
	}

	if svc.Name != "nginx" {
		t.Errorf("Expected name nginx, got %s", svc.Name)
	}
	if !svc.Active {
		t.Error("Expected active to be true")
	}
	if !svc.Enabled {
		t.Error("Expected enabled to be true")
	}
	if svc.PID != 1234 {
		t.Errorf("Expected PID 1234, got %d", svc.PID)
	}
}

func TestDiskStatus(t *testing.T) {
	disk := DiskStatus{
		Mountpoint: "/",
		UsedPct:    85.5,
		Available:  "10GB",
		Filesystem: "/dev/sda1",
	}

	if disk.Mountpoint != "/" {
		t.Errorf("Expected mountpoint /, got %s", disk.Mountpoint)
	}
	if disk.UsedPct != 85.5 {
		t.Errorf("Expected UsedPct 85.5, got %f", disk.UsedPct)
	}
	if disk.Available != "10GB" {
		t.Errorf("Expected Available 10GB, got %s", disk.Available)
	}
}
