package system

import (
	"context"
	"testing"
)

func TestNormalizeDistro(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"ubuntu", "ubuntu", "ubuntu"},
		{"debian", "debian", "debian"},
		{"rhel", "rhel", "rhel"},
		{"arch", "arch", "arch"},
		{"unknown", "someother", "someother"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeDistro(tt.input)
			if got != tt.want {
				t.Errorf("normalizeDistro(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsDebian(t *testing.T) {
	if !IsDebian("ubuntu") {
		t.Error("ubuntu should be debian-based")
	}
	if !IsDebian("debian") {
		t.Error("debian should be debian-based")
	}
	if IsDebian("rhel") {
		t.Error("rhel should not be debian-based")
	}
}

func TestIsRHEL(t *testing.T) {
	if !IsRHEL("rhel") {
		t.Error("rhel should be rhel-based")
	}
	if IsRHEL("ubuntu") {
		t.Error("ubuntu should not be rhel-based")
	}
}

func TestIsArch(t *testing.T) {
	if !IsArch("arch") {
		t.Error("arch should be arch-based")
	}
	if IsArch("ubuntu") {
		t.Error("ubuntu should not be arch-based")
	}
}

func TestGetOSInfo(t *testing.T) {
	ctx := context.Background()
	info := GetOSInfo(ctx)

	if info == nil {
		t.Fatal("GetOSInfo() returned nil")
	}
	if info.System == "" {
		t.Error("System is empty")
	}
}

func TestGetAuthLogPath(t *testing.T) {
	ctx := context.Background()
	path := GetAuthLogPath(ctx)
	if path == "" {
		t.Error("GetAuthLogPath() returned empty")
	}
}
