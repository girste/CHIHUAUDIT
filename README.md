# MCP Cybersec Watchdog

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![CI](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/ci.yml/badge.svg?branch=go)](https://github.com/girste/mcp-cybersec-watchdog/actions)
[![codecov](https://codecov.io/gh/girste/mcp-cybersec-watchdog/branch/go/graph/badge.svg)](https://codecov.io/gh/girste/mcp-cybersec-watchdog/tree/go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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

## Governance

- Issues and PRs welcome
- Security vulnerabilities: open a private security advisory
- Code of Conduct: be respectful

## License

MIT
