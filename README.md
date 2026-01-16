# MCP Cybersec Watchdog

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![CI](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/ci.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions)
[![CodeQL](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/codeql.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/security/code-scanning)
[![Trivy](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/trivy.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/trivy.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/girste/mcp-cybersec-watchdog/badge)](https://securityscorecards.dev/viewer/?uri=github.com/girste/mcp-cybersec-watchdog)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Release](https://img.shields.io/github/v/release/girste/mcp-cybersec-watchdog)](https://github.com/girste/mcp-cybersec-watchdog/releases)
[![Downloads](https://img.shields.io/github/downloads/girste/mcp-cybersec-watchdog/total)](https://github.com/girste/mcp-cybersec-watchdog/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

![MCP Cybersec Watchdog](cover-watchdog-mcp.png)

**Linux security audit tool.** Single 8MB binary, no dependencies.

Analyzes firewall, SSH, fail2ban, Docker, kernel hardening, SSL certificates, network services, and more. Includes continuous monitoring with anomaly detection.

## MCP Tools

`security_audit` `scan_app_security` `scan_network_security` `scan_database_security` `verify_backup_config` `check_vulnerability_intel` `start_monitoring` `stop_monitoring` `monitoring_status` `analyze_anomaly` `cleanup_old_logs`

## Commands

| Command | Description |
|---------|-------------|
| `test` | Run security audit |
| `verify` | Check prerequisites |
| `monitor` | Start continuous monitoring |
| `monitor-status` | Show daemon status |

## Quick Start

```bash
# Build
make build

# Run audit
sudo ./bin/mcp-watchdog test

# Start monitoring
sudo ./bin/mcp-watchdog monitor
```

## Architecture

```
internal/
├── analyzers/   # Security checks (13 analyzers)
├── scanners/    # Advanced scans (5 scanners)
├── monitoring/  # Daemon + anomaly detection
└── mcp/         # MCP server (11 tools)
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

## License

[MIT](LICENSE)
