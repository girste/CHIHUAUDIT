package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCommandExists(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want bool
	}{
		{"existing command", "sh", true},
		{"non-existing command", "nonexistentcommand12345", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CommandExists(tt.cmd)
			if got != tt.want {
				t.Errorf("CommandExists(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestFileExists(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	_ = os.WriteFile(tmpFile, []byte("test"), 0644)

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"existing file", tmpFile, true},
		{"non-existing file", filepath.Join(tmpDir, "nonexistent.txt"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FileExists(tt.path)
			if got != tt.want {
				t.Errorf("FileExists(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestTryPaths(t *testing.T) {
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")
	_ = os.WriteFile(file2, []byte("test"), 0644)

	tests := []struct {
		name  string
		paths []string
		want  string
	}{
		{"first exists", []string{file2, file1}, file2},
		{"second exists", []string{file1, file2}, file2},
		{"none exist", []string{file1, "/nonexistent"}, ""},
		{"empty list", []string{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TryPaths(tt.paths...)
			if got != tt.want {
				t.Errorf("TryPaths() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectFirewall(t *testing.T) {
	result := DetectFirewall()
	// Just ensure it returns a string (empty or valid)
	if result != "" && result != "ufw" && result != "firewalld" && result != "iptables" {
		t.Errorf("DetectFirewall() = %q, want empty or valid firewall", result)
	}
}

func TestDetectPackageManager(t *testing.T) {
	result := DetectPackageManager()
	validPMs := []string{"", "apt", "dnf", "yum", "pacman", "apk"}
	valid := false
	for _, pm := range validPMs {
		if result == pm {
			valid = true
			break
		}
	}
	if !valid {
		t.Errorf("DetectPackageManager() = %q, want valid package manager", result)
	}
}

func TestDetectInitSystem(t *testing.T) {
	result := DetectInitSystem()
	validInits := []string{"systemd", "sysvinit", "unknown"}
	valid := false
	for _, init := range validInits {
		if result == init {
			valid = true
			break
		}
	}
	if !valid {
		t.Errorf("DetectInitSystem() = %q, want valid init system", result)
	}
}
