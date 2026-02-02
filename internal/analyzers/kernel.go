package analyzers

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
)

type KernelAnalyzer struct{}

func (a *KernelAnalyzer) Name() string           { return "kernel" }
func (a *KernelAnalyzer) RequiresSudo() bool     { return true }
func (a *KernelAnalyzer) Timeout() time.Duration { return system.TimeoutMedium }

// Key kernel security parameters to check
var kernelParams = map[string]string{
	// Network security
	"net.ipv4.conf.all.accept_source_route":      "0",
	"net.ipv4.conf.all.send_redirects":           "0",
	"net.ipv4.tcp_syncookies":                    "1",
	"net.ipv4.conf.all.accept_redirects":         "0",
	"net.ipv4.conf.all.secure_redirects":         "0",
	"net.ipv4.conf.all.log_martians":             "1",
	"net.ipv4.icmp_echo_ignore_broadcasts":       "1",
	"net.ipv4.icmp_ignore_bogus_error_responses": "1",
	"net.ipv4.conf.all.rp_filter":                "1",

	// Kernel hardening
	"kernel.kptr_restrict":             "2",
	"kernel.dmesg_restrict":            "1",
	"kernel.yama.ptrace_scope":         "1",
	"kernel.kexec_load_disabled":       "1",
	"kernel.unprivileged_bpf_disabled": "1",

	// Filesystem
	"fs.protected_hardlinks": "1",
	"fs.protected_symlinks":  "1",
	"fs.suid_dumpable":       "0",
}

func (a *KernelAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	secureCount := 0
	totalCount := len(kernelParams)
	insecureParams := []string{}

	for param, expectedValue := range kernelParams {
		sysctlResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "sysctl", "-n", param)
		if sysctlResult == nil || !sysctlResult.Success {
			continue
		}

		actualValue := strings.TrimSpace(sysctlResult.Stdout)
		if actualValue == expectedValue {
			secureCount++
		} else {
			insecureParams = append(insecureParams, param)
		}
	}

	hardeningPercentage := (float64(secureCount) / float64(totalCount)) * 100

	result.Data = map[string]interface{}{
		"totalParamsChecked":  totalCount,
		"secureParams":        secureCount,
		"hardeningPercentage": hardeningPercentage,
		"insecureParams":      insecureParams,
	}

	// Add issues based on hardening percentage
	if hardeningPercentage < 50 {
		result.AddIssue(NewIssue(SeverityCritical, "Poor kernel hardening: "+strconv.FormatFloat(hardeningPercentage, 'f', 1, 64)+"%", "Review and apply kernel security parameters"))
	} else if hardeningPercentage < 75 {
		result.AddIssue(NewIssue(SeverityMedium, "Moderate kernel hardening: "+strconv.FormatFloat(hardeningPercentage, 'f', 1, 64)+"%", "Improve kernel security parameters"))
	}

	return result, nil
}
