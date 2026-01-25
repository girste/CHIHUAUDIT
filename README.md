# MCP Cybersec Watchdog

![MCP Cybersec Watchdog](cover-watchdog-mcp.png)

[![CI](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/ci.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions)
[![Lint](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/lint.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/lint.yml)
[![CodeQL](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/codeql.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/security/code-scanning)
[![Trivy](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/trivy.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/trivy.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/girste/mcp-cybersec-watchdog/badge)](https://securityscorecards.dev/viewer/?uri=github.com/girste/mcp-cybersec-watchdog)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Mentioned in Awesome](https://awesome.re/mentioned-badge.svg)](https://github.com/punkpeye/awesome-mcp-servers)

**Linux security audit tool.** Single 8.1MB binary, no dependencies.

Analyzes firewall, SSH, fail2ban, Docker, kernel hardening, SSL certificates, network services, and more. Includes continuous monitoring with anomaly detection and EU Vulnerability Database integration.

**Just want to use it?** Download the latest binary from [Releases](https://github.com/girste/mcp-cybersec-watchdog/releases) — no compilation needed.

## MCP Tools

- **security_audit** — Complete system security analysis
- **cis_audit** — CIS Benchmark Ubuntu 22.04 compliance check
- **scan_app_security** — Application layer security (ports, processes, containers)
- **scan_network_security** — Network configuration & firewall rules
- **scan_database_security** — Database exposure & hardening
- **scan_waf_cdn** — WAF/CDN detection & SSL/TLS analysis
- **verify_backup_config** — Backup integrity verification
- **check_vulnerability_intel** — CVE database lookup (EU Vulnerability Database)
- **start_monitoring** / **stop_monitoring** — Continuous monitoring daemon
- **monitoring_status** — Daemon status & statistics
- **analyze_anomaly** — Anomaly detection analysis
- **cleanup_old_logs** — Log rotation
- **configure_webhook** / **test_webhook** — Discord/Slack/custom webhooks
- **get_notification_config** — Show notification settings

## Example Output

📄 **[View all output examples →](docs/outputs/)** - Full audit reports, CIS benchmarks, network scans, monitoring alerts, and webhook notifications with screenshots.

<details>
<summary>Quick preview: Security Audit</summary>

```
═══════════════════════════════════════════════════════════════
  🟡  SECURITY REPORT  -  production-web-01
═══════════════════════════════════════════════════════════════

  Status: 🟡 WARNINGS - Some security issues detected
  Score:  72/100 (Grade: C)

───────────────────────────────────────────────────────────────
  ✅ WHAT'S WORKING WELL
───────────────────────────────────────────────────────────────
  • Firewall active • SSH hardened • Fail2ban protecting
  • AppArmor enforcing • System updated • Kernel hardened

───────────────────────────────────────────────────────────────
  ⚠️  ISSUES REQUIRING ATTENTION
───────────────────────────────────────────────────────────────
  🔴 [HIGH] Docker daemon exposed without TLS
  ⚠️ [MEDIUM] MySQL listening on 0.0.0.0:3306
  ⚠️ [MEDIUM] Last backup is 8 days old

═══════════════════════════════════════════════════════════════
```

</details>

## Commands

| Command | Description |
|---------|-------------|
| `audit` | Run security audit with standardized output |
| `test` | Run security audit (legacy JSON output) |
| `verify` | Check prerequisites |
| `monitor` | Start continuous monitoring |
| `monitor-status` | Show daemon status |

## Quick Start

```bash
# Download binary (no build required)
wget https://github.com/girste/mcp-cybersec-watchdog/releases/latest/download/mcp-watchdog
chmod +x mcp-watchdog

# Run audit
sudo ./mcp-watchdog audit
```

**For developers:**

```bash
make build
sudo ./bin/mcp-watchdog audit
```

## Architecture

```
internal/
├── analyzers/   # Security checks (firewall, SSH, fail2ban, etc.)
├── audit/       # Core audit orchestration
├── cis/         # CIS Benchmark Ubuntu 22.04 (60 controls)
├── config/      # Configuration management
├── mcp/         # MCP server (16 tools)
├── monitoring/  # Continuous monitoring daemon + anomaly detection
├── notify/      # Discord/Slack/Webhook notifications
├── output/      # Standardized output formatter (traffic light system)
├── scanners/    # Advanced scans (network, WAF, database, vulnerability intel)
├── system/      # System information utilities
└── util/        # Helper functions
```

---

## Contributing

1. Fork the repo
2. Create a branch (`git checkout -b feature/your-feature`)
3. Make changes and run `make lint`
4. Commit (`git commit -m "Add feature"`)
5. Push and open a PR

**Code standards:** Go 1.23+, `gofmt`, pass `golangci-lint`.

## Security

**Do not report vulnerabilities via public issues.**

Open a [private security advisory](https://github.com/girste/mcp-cybersec-watchdog/security/advisories/new) or DM [@girste](https://github.com/girste).

This tool requires sudo for read-only access to system info (firewall, logs, services). No write access is granted.

---

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Release](https://img.shields.io/github/v/release/girste/mcp-cybersec-watchdog)](https://github.com/girste/mcp-cybersec-watchdog/releases)
[![Downloads](https://img.shields.io/github/downloads/girste/mcp-cybersec-watchdog/total)](https://github.com/girste/mcp-cybersec-watchdog/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
