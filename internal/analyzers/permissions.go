package analyzers

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
)

type PermissionsAnalyzer struct{}

func (a *PermissionsAnalyzer) Name() string           { return "permissions" }
func (a *PermissionsAnalyzer) RequiresSudo() bool     { return true }
func (a *PermissionsAnalyzer) Timeout() time.Duration { return system.TimeoutShort }

// permCheck defines expected maximum permissions for a critical file.
// Any permission bit set in the actual mode that is NOT in maxPerm triggers an alert.
type permCheck struct {
	path     string
	maxPerm  os.FileMode
	severity Severity
	message  string
	fix      string
}

var criticalFileChecks = []permCheck{
	// /etc/shadow: root:shadow 640 — others must have zero access
	{"/etc/shadow", 0640, SeverityCritical, "/etc/shadow readable by non-shadow users", "chmod 640 /etc/shadow"},
	// /etc/passwd: root:root 644 — must not be writable by group/others
	{"/etc/passwd", 0644, SeverityHigh, "/etc/passwd writable by non-root", "chmod 644 /etc/passwd"},
	// /etc/ssh/sshd_config: must not be writable by group/others (readable is ok)
	{"/etc/ssh/sshd_config", 0644, SeverityHigh, "/etc/ssh/sshd_config writable by non-root", "chmod 600 /etc/ssh/sshd_config"},
}

func (a *PermissionsAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	checked := []map[string]interface{}{}

	// Check predefined critical files
	for _, check := range criticalFileChecks {
		hostPath := system.HostPath(check.path)
		info, err := os.Stat(hostPath)
		if err != nil {
			continue
		}

		perm := info.Mode().Perm()
		checked = append(checked, map[string]interface{}{
			"path": check.path,
			"perm": fmt.Sprintf("%04o", perm),
		})

		// Flag if actual permissions exceed the allowed maximum
		if (perm &^ check.maxPerm) != 0 {
			result.AddIssue(NewIssue(check.severity,
				fmt.Sprintf("%s: permissions %04o (expected max %04o)", check.path, perm, check.maxPerm),
				check.fix))
		}
	}

	// Check SSH host private keys — should be 0600 (owner-only)
	sshDir := system.HostPath("/etc/ssh")
	if entries, err := os.ReadDir(sshDir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			// Private keys: ssh_host_*_key (not .pub)
			if !strings.HasPrefix(name, "ssh_host_") || strings.HasSuffix(name, ".pub") {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			perm := info.Mode().Perm()
			checked = append(checked, map[string]interface{}{
				"path": "/etc/ssh/" + name,
				"perm": fmt.Sprintf("%04o", perm),
			})
			if (perm & 0077) != 0 {
				result.AddIssue(NewIssue(SeverityHigh,
					fmt.Sprintf("/etc/ssh/%s: permissions %04o (expected 0600)", name, perm),
					fmt.Sprintf("chmod 600 /etc/ssh/%s", name)))
			}
		}
	}

	result.Data = map[string]interface{}{
		"checkedFiles": checked,
		"fileCount":    len(checked),
	}

	return result, nil
}
