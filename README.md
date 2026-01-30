# MCP Cybersec Watchdog

<div align="center">

[![Mentioned in Awesome](https://awesome.re/mentioned-badge.svg)](https://github.com/punkpeye/awesome-mcp-servers)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/girste/mcp-cybersec-watchdog/badge)](https://securityscorecards.dev/viewer/?uri=github.com/girste/mcp-cybersec-watchdog)

</div>

![MCP Cybersec Watchdog](docs/images/cover-watchdog-mcp.png)

[![CI](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/ci.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions)
[![Lint](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/lint.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/lint.yml)
[![CodeQL](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/codeql.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/security/code-scanning)
[![Trivy](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/trivy.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/trivy.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11858/badge)](https://www.bestpractices.dev/projects/11858)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

**Linux security audit tool for AI assistants.** Single 8.1MB static binary, zero dependencies.

Analyzes firewall, SSH, fail2ban, Docker, kernel hardening, SSL certificates, network services, and more. Includes continuous monitoring with anomaly detection and EU Vulnerability Database integration.

**Download:** Get the latest binary from [Releases](https://github.com/girste/mcp-cybersec-watchdog/releases) — no compilation needed.

## MCP Tools

- **security_audit** — Complete system security analysis
- **cis_audit** — CIS Benchmark compliance check
- **scan_app_security** — Ports, processes, containers
- **scan_network_security** — Network & firewall rules
- **scan_database_security** — Database exposure & hardening
- **scan_waf_cdn** — WAF/CDN detection & SSL/TLS
- **verify_backup_config** — Backup integrity
- **check_vulnerability_intel** — CVE database lookup (EU Vulnerability Database)
- **start_monitoring** / **stop_monitoring** / **monitoring_status** — Continuous monitoring daemon
- **analyze_anomaly** — AI anomaly detection analysis
- **cleanup_old_logs** — Log rotation
- **configure_webhook** / **test_webhook** / **get_notification_config** — Discord/Slack/custom webhooks
- **manage_whitelist** — AI-driven whitelist for false positives

## Features

### AI-Driven Whitelist
Eliminate false positives with AI-managed `.mcp-watchdog-whitelist.yaml`. Ask AI to identify false positives → automatic whitelisting → clean results. See `.mcp-watchdog-whitelist.example.yaml` for template.

### Discord/Slack Webhooks
Customizable security alerts with rich embeds, severity colors, and detailed breakdowns.

![Discord Webhook Example](docs/images/screen-discord.png)

## Quick Start

```bash
# Download binary
wget https://github.com/girste/mcp-cybersec-watchdog/releases/latest/download/mcp-watchdog_linux_amd64.tar.gz
tar xzf mcp-watchdog_linux_amd64.tar.gz
chmod +x mcp-watchdog

# Run audit
sudo ./mcp-watchdog audit

# Or build from source
make build && sudo ./bin/mcp-watchdog audit
```

📄 **[View all output examples](docs/outputs/)** - Full audit reports, CIS benchmarks, monitoring alerts, webhook notifications.

## Security

**Do not report vulnerabilities via public issues.** Open a [private security advisory](https://github.com/girste/mcp-cybersec-watchdog/security/advisories/new) or DM [@girste](https://github.com/girste).

This tool requires sudo for read-only access to system info (firewall, logs, services). No write operations.

---

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Release](https://img.shields.io/github/v/release/girste/mcp-cybersec-watchdog)](https://github.com/girste/mcp-cybersec-watchdog/releases)
[![Downloads](https://img.shields.io/github/downloads/girste/mcp-cybersec-watchdog/total)](https://github.com/girste/mcp-cybersec-watchdog/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

# Test
