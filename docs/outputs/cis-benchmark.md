# CIS Benchmark - Ubuntu 22.04

CIS compliance check output (60+ security controls).

```bash
sudo ./bin/mcp-watchdog audit --cis
```

## Output Example

```
═══════════════════════════════════════════════════════════════
  CIS BENCHMARK - Ubuntu 22.04 LTS
═══════════════════════════════════════════════════════════════

  Compliance Score: 85% (51/60 controls passed)
  Level: Level 1 Server

───────────────────────────────────────────────────────────────
  ✅ PASSED CONTROLS
───────────────────────────────────────────────────────────────

  [1.1.1.1] ✅ Ensure mounting of cramfs filesystems is disabled
  [1.1.1.2] ✅ Ensure mounting of freevxfs filesystems is disabled
  [1.3.1] ✅ Ensure AIDE is installed
  [1.4.1] ✅ Ensure bootloader password is set
  [1.5.1] ✅ Ensure permissions on /etc/passwd are configured
  [1.5.2] ✅ Ensure permissions on /etc/shadow are configured
  [2.1.1] ✅ Ensure xinetd is not installed
  [3.1.1] ✅ Ensure IP forwarding is disabled
  [3.2.1] ✅ Ensure source routed packets are not accepted
  [4.1.1.1] ✅ Ensure auditd is installed
  [5.2.1] ✅ Ensure permissions on /etc/ssh/sshd_config are configured
  [5.2.4] ✅ Ensure SSH Protocol is set to 2
  [5.2.5] ✅ Ensure SSH LogLevel is appropriate
  [5.2.8] ✅ Ensure SSH root login is disabled
  [5.2.10] ✅ Ensure SSH PermitUserEnvironment is disabled
  ... (36 more passed controls)

───────────────────────────────────────────────────────────────
  ❌ FAILED CONTROLS
───────────────────────────────────────────────────────────────

  [1.1.22] ❌ Ensure sticky bit is set on all world-writable directories
    Remediation: Run 'df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs chmod a+t'

  [3.3.3] ❌ Ensure IPv6 router advertisements are not accepted
    Remediation: Add 'net.ipv6.conf.all.accept_ra = 0' to /etc/sysctl.conf

  [4.1.12] ❌ Ensure successful file system mounts are collected
    Remediation: Add audit rules for mount syscalls

  [5.2.15] ❌ Ensure SSH warning banner is configured
    Remediation: Set 'Banner /etc/issue.net' in /etc/ssh/sshd_config

  ... (5 more failed controls)

═══════════════════════════════════════════════════════════════
  📊 SUMMARY BY SECTION
═══════════════════════════════════════════════════════════════

  Section 1 - Initial Setup:           12/15 passed (80%)
  Section 2 - Services:                 8/8 passed (100%)
  Section 3 - Network Configuration:    7/10 passed (70%)
  Section 4 - Logging and Auditing:     9/12 passed (75%)
  Section 5 - Access Control:          15/15 passed (100%)

═══════════════════════════════════════════════════════════════
```
