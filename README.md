# 🐕 MCP Cybersec Watchdog

**Complete Linux security audit in 30 seconds** via Claude MCP. Analyzes firewall, SSH, threats, fail2ban, Docker, kernel hardening and more. Zero configuration required.

**🚀 Live Monitoring (Beta)**: Continuous background monitoring with anomaly detection and AI alerts.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/test.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/test.yml)

## What It Does

**Security Audit:**
- Firewall (ufw/iptables/firewalld), SSH config, network services
- Failed login attempts, attack patterns, fail2ban status
- Docker security, kernel hardening (16+ params), MAC (AppArmor/SELinux)
- Returns actionable recommendations with specific commands

**Live Monitoring:**
- Background daemon checks server every 5min-24h (default: 1 hour)
- Detects: firewall changes, new open ports, SSH config changes, attack spikes
- AI analysis only when anomalies detected (token-efficient!)
- Auto-cleanup prevents disk fill

## Installation

```bash
pip install mcp-cybersec-watchdog

# Setup passwordless sudo (required for full analysis)
bash <(curl -s https://raw.githubusercontent.com/girste/mcp-cybersec-watchdog/main/setup-sudo.sh)
```

## Usage

### Standalone

```bash
# One-time security audit
mcp-watchdog test

# Live monitoring (checks every hour)
mcp-watchdog monitor

# Custom interval (e.g., every 30 minutes)
mcp-watchdog monitor --interval 1800
```

### With Claude Desktop

Add to Claude config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "cybersec-watchdog": {
      "command": "/path/to/venv/bin/mcp-watchdog"
    }
  }
}
```

**MCP Tools Available:**

| Tool | Description |
|------|-------------|
| `security_audit` | One-time comprehensive audit |
| `start_monitoring` | Start background monitoring (default: 1h interval) |
| `stop_monitoring` | Stop monitoring daemon |
| `monitoring_status` | Check daemon status and recent bulletins |
| `analyze_anomaly` | AI analysis of detected anomalies |

**Example prompts:**
```
Run a security audit on this server
Start monitoring with 30 minute intervals
Show monitoring status
```

## Output Example

```json
{
  "firewall": {"type": "ufw", "active": true, "open_ports": [80, 443, 2244]},
  "ssh": {"port": 2244, "permit_root_login": "no", "password_auth": "no"},
  "threats": {"total_attempts": 342, "unique_ips": 89},
  "fail2ban": {"active": true, "total_banned": 12},
  "docker": {"running_containers": 1, "rootless": false},
  "kernel_hardening": {"hardening_percentage": 100.0},
  "recommendations": [...]
}
```

**Privacy**: IPs and hostnames are masked by default (`91.99.***.***`, `srv-ab**`). Disable with `{"mask_data": false}`.

## Configuration (Optional)

Create `.mcp-security.json` to customize:

```json
{
  "checks": {"docker": false, "updates": false},
  "threat_analysis_days": 14,
  "mask_data": false
}
```

## Development

```bash
git clone https://github.com/girste/mcp-cybersec-watchdog
cd mcp-cybersec-watchdog
pip install -e ".[dev]"
pytest tests/ -v
```

CI: Python 3.10/3.11/3.12 via GitHub Actions.

## Roadmap

- [x] Live monitoring mode ✅
- [ ] CVE scanning
- [ ] SSL certificate checks
- [ ] CIS benchmark compliance

## Contributing

PRs welcome! Fork, create feature branch, add tests, submit PR.

## License

MIT - see [LICENSE](LICENSE)

---

Created by [Girste](https://girste.com) • [Report issues](https://github.com/girste/mcp-cybersec-watchdog/issues)
