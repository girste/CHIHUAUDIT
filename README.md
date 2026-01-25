# MCP Cybersec Watchdog

![MCP Cybersec Watchdog](cover-watchdog-mcp.png)

[![CI](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/ci.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions)
[![Lint](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/lint.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/lint.yml)
[![CodeQL](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/codeql.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/security/code-scanning)
[![Trivy](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/trivy.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/trivy.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/girste/mcp-cybersec-watchdog/badge)](https://securityscorecards.dev/viewer/?uri=github.com/girste/mcp-cybersec-watchdog)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Mentioned in Awesome](https://awesome.re/mentioned-badge.svg)](https://github.com/punkpeye/awesome-mcp-servers)

**Linux security audit tool.** Single 8MB binary, no dependencies.

Analyzes firewall, SSH, fail2ban, Docker, kernel hardening, SSL certificates, network services, and more. Includes continuous monitoring with anomaly detection.

## MCP Tools

`security_audit` `cis_audit` `scan_app_security` `scan_network_security` `scan_database_security` `scan_waf_cdn` `verify_backup_config` `check_vulnerability_intel` `start_monitoring` `stop_monitoring` `monitoring_status` `analyze_anomaly` `cleanup_old_logs` `configure_webhook` `test_webhook` `get_notification_config`

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
# Build
make build

# Run audit with visual output
sudo ./bin/mcp-watchdog audit

# Run audit for cron (notify only on issues)
sudo ./bin/mcp-watchdog audit --quiet --webhook --on-issues

# JSON output for scripts
sudo ./bin/mcp-watchdog audit --format=json

# Start monitoring
sudo ./bin/mcp-watchdog monitor
```

## Architecture

```
internal/
├── analyzers/   # Security checks (13 analyzers)
├── scanners/    # Advanced scans (6 scanners)
├── cis/         # CIS Benchmark Ubuntu 22.04 (60 controls)
├── monitoring/  # Daemon + anomaly detection
├── notify/      # Discord/Slack/Webhook notifications
├── output/      # Standardized output formatter
└── mcp/         # MCP server (16 tools)
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
