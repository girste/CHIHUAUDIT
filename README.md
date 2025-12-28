# 🐕 MCP Cybersec Watchdog

> Cybersecurity monitoring and analysis for Linux servers via MCP

Get a **complete security audit in 30 seconds**. Analyzes firewall, SSH, threats, fail2ban, Docker, kernel hardening and more. Returns actionable recommendations with zero configuration.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/test.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/badge/PyPI-ready-green.svg)](https://pypi.org)

## Why?

Security audits are tedious. This tool gives you:
- **Complete security report in 30 seconds**
- **Factual analysis** - no subjective scoring, just data
- **AI-friendly JSON output** for integration with LLMs
- **Privacy-first** approach (data masking by default)
- **Actionable recommendations** with specific commands
- **Zero configuration** - works out of the box

## Features

✅ **Firewall Analysis** - Detects and analyzes ufw, iptables, or firewalld
✅ **SSH Hardening Check** - Validates sshd_config security settings
✅ **Threat Intelligence** - Analyzes failed login attempts and patterns
✅ **Fail2ban Integration** - Reports jail status and banned IPs
✅ **Privacy Masking** - Automatically masks sensitive data
✅ **Cross-distro** - Works on Debian, Ubuntu, RHEL, CentOS

## Quick Start

### Installation

```bash
pip install mcp-cybersec-watchdog

# Setup passwordless sudo (one-time, required for full analysis)
bash <(curl -s https://raw.githubusercontent.com/girste/mcp-cybersec-watchdog/main/setup-sudo.sh)
```

Or manual install:
```bash
git clone https://github.com/girste/mcp-cybersec-watchdog
cd mcp-cybersec-watchdog
pip install -e .
./setup-sudo.sh
```

### Standalone Usage

```bash
# Run one-time security audit
mcp-watchdog test

# Run continuous monitoring (default: checks every hour)
mcp-watchdog monitor

# Run single monitoring check (useful for testing)
mcp-watchdog monitor-once

# Custom monitoring interval (check every 30 minutes)
mcp-watchdog monitor --interval 1800
```

### Live Monitoring

The monitoring mode provides:
- **Baseline tracking**: First run creates security baseline
- **Anomaly detection**: Detects configuration changes, new open ports, attack spikes
- **Smart alerting**: AI analysis triggered ONLY when anomalies detected (saves tokens!)
- **Bulletins**: Human-readable reports written to log directory

**Example workflow**:
```bash
# Start monitoring
mcp-watchdog monitor --interval 3600

# Output every hour:
# ✓ ALL OK → Simple bulletin (no AI needed)
# ⚠ ANOMALY DETECTED → AI analysis recommended
```

When anomalies are detected, the tool writes detailed JSON reports that can be analyzed via the MCP `analyze_anomaly` tool (AI-powered deep analysis).

### MCP Integration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "cybersec-watchdog": {
      "command": "/path/to/venv/bin/mcp-watchdog",
      "env": {}
    }
  }
}
```

Or use the included config file:
```bash
cp claude_desktop_config.json ~/Library/Application\ Support/Claude/
```

Then from Claude Desktop:

```
Run a security audit on this server
```

The tool will return a comprehensive JSON report with all security findings.

### MCP Tools

The server exposes two tools to Claude:

**1. `security_audit`** - One-time comprehensive security audit
```
Run a security audit on this server
```

**2. `analyze_anomaly`** - AI-powered anomaly analysis (token-efficient!)
```
Analyze the anomaly in /var/log/mcp-watchdog/anomaly_20251228_123456.json
```

This tool is automatically suggested when monitoring detects anomalies. It provides deep AI insights only when needed, saving tokens during normal operations.

## Example Output

```json
{
  "timestamp": "2025-12-27T13:20:39Z",
  "hostname": "srv-pr**",
  "os": "Linux (debian)",
  "kernel": "6.8.0-87-generic",
  "firewall": {
    "type": "ufw",
    "active": true,
    "default_policy": "deny",
    "rules_count": 8,
    "open_ports": [80, 443, 2244]
  },
  "ssh": {
    "port": 2244,
    "permit_root_login": "no",
    "password_auth": "no",
    "pubkey_auth": "yes",
    "issues": []
  },
  "threats": {
    "period_days": 7,
    "total_attempts": 342,
    "unique_ips": 89,
    "top_attackers": [
      {"ip": "45.142.***.***", "attempts": 67}
    ],
    "patterns": ["ssh_brute_force"]
  },
  "fail2ban": {
    "installed": true,
    "active": true,
    "total_banned": 12
  },
  "recommendations": []
}
```

## Configuration

Optional config file (`.mcp-security.json` in current dir or home):

```json
{
  "checks": {
    "docker": false,
    "updates": false
  },
  "threat_analysis_days": 14,
  "mask_data": false
}
```

Disable specific checks or customize analysis period. All checks enabled by default.

## Privacy

By default, the tool **masks sensitive data**:
- IP addresses: `91.99.***.***`
- Hostnames: `srv-ab**`

Disable masking via config file or MCP parameter `{"mask_data": false}`

## Requirements

- Python 3.10+
- Linux (Debian/Ubuntu/RHEL/CentOS)
- sudo access (passwordless sudo for automated operation)

### Sudo Configuration

The tool auto-detects missing permissions and warns you with setup instructions. It needs sudo access for:
- **Firewall analysis**: `ufw`, `iptables`, `firewalld`
- **Fail2ban status**: `fail2ban-client`
- **Log analysis**: `/var/log/auth.log`

Setup passwordless sudo for these specific commands:

```bash
./setup-sudo.sh
```

Creates `/etc/sudoers.d/mcp-security` with minimal permissions. The tool continues with limited analysis if sudo is not configured.

## What Gets Analyzed

### Firewall
- Active status
- Default policy (allow/deny)
- Number of rules
- Open ports

### SSH Configuration
- Port number
- Root login status
- Password authentication
- Pubkey authentication

### Threats
- Failed SSH login attempts (7 days)
- Unique attacker IPs
- Attack patterns (brute force, distributed)
- Top 10 attackers

### Fail2ban
- Installation status
- Active jails
- Banned IPs count

## Development

```bash
# Clone repo
git clone https://github.com/girste/mcp-cybersec-watchdog
cd mcp-cybersec-watchdog

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Test standalone
mcp-watchdog test
```

CI runs automatically on push via GitHub Actions (Python 3.10/3.11/3.12).

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes (keep code clean and concise)
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details

## Roadmap

- [ ] CVE scanning for installed packages
- [ ] SSL certificate expiration checks
- [ ] Continuous monitoring mode
- [ ] HTML/PDF report export
- [ ] CIS benchmark compliance checks

## Author

Created by [Girste](https://girste.com)

## Support

- 🐛 [Report bugs](https://github.com/girste/mcp-cybersec-watchdog/issues)
- 💡 [Request features](https://github.com/girste/mcp-cybersec-watchdog/issues)
- ⭐ Star this repo if you find it useful!
