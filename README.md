# MCP Cybersec Watchdog

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![CI](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/ci.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions)
[![CodeQL](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/codeql.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/security/code-scanning)
[![Go Report Card](https://goreportcard.com/badge/github.com/girste/mcp-cybersec-watchdog)](https://goreportcard.com/report/github.com/girste/mcp-cybersec-watchdog)
[![Release](https://img.shields.io/github/v/release/girste/mcp-cybersec-watchdog?include_prereleases)](https://github.com/girste/mcp-cybersec-watchdog/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

![MCP Cybersec Watchdog](cover-watchdog-mcp.png)

**Linux security audit tool for Claude Desktop.** Single 8MB binary, no dependencies.

Analyzes firewall, SSH, fail2ban, Docker, kernel hardening, SSL certificates, network services, and more. Includes continuous monitoring with anomaly detection.

## Quick Start

```bash
# Build
make build

# Run audit
sudo ./bin/mcp-watchdog test

# Start monitoring
sudo ./bin/mcp-watchdog monitor
```

## Claude Desktop

```json
{
  "mcpServers": {
    "cybersec-watchdog": {
      "command": "/path/to/mcp-watchdog"
    }
  }
}
```

## Commands

| Command | Description |
|---------|-------------|
| `test` | Run security audit |
| `verify` | Check prerequisites |
| `monitor` | Start continuous monitoring |
| `monitor-status` | Show daemon status |

## MCP Tools

`security_audit` `scan_app_security` `scan_network_security` `scan_database_security` `verify_backup_config` `check_vulnerability_intel` `start_monitoring` `stop_monitoring` `monitoring_status` `analyze_anomaly` `cleanup_old_logs`

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

**Code standards:** Go 1.22+, `gofmt`, pass `golangci-lint`.

## Security

**Do not report vulnerabilities via public issues.**

Email: **security@girste.com** or open a [private security advisory](https://github.com/girste/mcp-cybersec-watchdog/security/advisories/new).

This tool requires sudo for read-only access to system info (firewall, logs, services). No write access is granted.

## License

[MIT](LICENSE)
