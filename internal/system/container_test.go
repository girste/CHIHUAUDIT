package system

import (
	"testing"
)

func TestHostPath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		inContainer bool
		want        string
	}{
		{
			name:        "native execution - absolute path",
			path:        "/etc/ssh/sshd_config",
			inContainer: false,
			want:        "/etc/ssh/sshd_config",
		},
		{
			name:        "container execution - absolute path",
			path:        "/etc/ssh/sshd_config",
			inContainer: true,
			want:        "/host/etc/ssh/sshd_config",
		},
		{
			name:        "container execution - already prefixed",
			path:        "/host/etc/ssh/sshd_config",
			inContainer: true,
			want:        "/host/etc/ssh/sshd_config",
		},
		{
			name:        "native execution - already prefixed (passthrough)",
			path:        "/host/etc/ssh/sshd_config",
			inContainer: false,
			want:        "/host/etc/ssh/sshd_config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original state
			originalHostRoot := hostRoot
			defer func() { hostRoot = originalHostRoot }()

			// Set container state
			if tt.inContainer {
				hostRoot = "/host"
			} else {
				hostRoot = ""
			}

			got := HostPath(tt.path)
			if got != tt.want {
				t.Errorf("HostPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsInContainer(t *testing.T) {
	tests := []struct {
		name     string
		hostRoot string
		want     bool
	}{
		{
			name:     "native execution",
			hostRoot: "",
			want:     false,
		},
		{
			name:     "container execution",
			hostRoot: "/host",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original state
			originalHostRoot := hostRoot
			defer func() { hostRoot = originalHostRoot }()

			hostRoot = tt.hostRoot

			got := IsInContainer()
			if got != tt.want {
				t.Errorf("IsInContainer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHostPathEdgeCases(t *testing.T) {
	// Save original state
	originalHostRoot := hostRoot
	defer func() { hostRoot = originalHostRoot }()

	hostRoot = "/host"

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "root path",
			path: "/",
			want: "/host/",
		},
		{
			name: "empty path",
			path: "",
			want: "/host",
		},
		{
			name: "relative path",
			path: "etc/config",
			want: "/hostetc/config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HostPath(tt.path)
			if got != tt.want {
				t.Errorf("HostPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
