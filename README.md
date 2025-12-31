# 🐕 MCP Cybersec Watchdog

**Complete Linux security audit in 30 seconds** via Claude MCP. Analyzes firewall, SSH, threats, fail2ban, Docker, kernel hardening and more. Zero configuration required.

**🚀 Live Monitoring (Beta)**: Continuous background monitoring with anomaly detection and AI alerts.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/test.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/test.yml)

## What It Does

**Security Audit:**
- **Infrastructure**: Firewall, SSH config, network services, systemd health, disk usage
- **Vulnerabilities**: CVE scanning (critical packages), container image scanning (with trivy)
- **SSL/TLS**: Certificate expiry, validity, auto-renewal status
- **Compliance Standards**:
  - CIS Benchmark (Distribution Independent Linux v2.0)
  - NIST 800-53 Rev 5 baseline controls
  - PCI-DSS v4.0 technical requirements
- **Runtime Security**: Docker/container security, kernel hardening (16+ params), MAC (AppArmor/SELinux)
- **Threat Detection**: Failed login attempts, attack patterns, fail2ban status
- Returns prioritized actionable recommendations

**Live Monitoring:**
- Background daemon checks server every 5min-24h (default: 1 hour)
- Detects: firewall changes, new open ports, SSH config changes, attack spikes, disk space issues
- Monitors: systemd failed units, critical services down, SSL expiry, container vulnerabilities
- Compliance drift detection: CIS, NIST, PCI-DSS baseline violations
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
  "firewall": {"type": "ufw", "active": true, "open_ports": [80, 443, 22]},
  "ssh": {"port": 22, "permit_root_login": "no", "password_auth": "no"},
  "ssl_certificates": {"total_certificates": 4, "expired": 0, "expiring_soon_30days": 0},
  "disk_usage": {"total_filesystems": 2, "critical_count": 0, "warning_count": 0},
  "cve_vulnerabilities": {"vulnerabilities_found": 0, "critical_vulnerabilities": 0},
  "cis_benchmark": {"compliance_percentage": 78.3, "passed": 18, "failed": 5},
  "nist_800_53": {"compliance_percentage": 40.0, "passed": 2, "failed": 3},
  "pci_dss": {"compliance_percentage": 80.0, "passed": 4, "failed": 1},
  "container_security": {"scanned_images": 1, "critical_vulnerabilities": 0},
  "services": {"systemd": {"failed_count": 0, "critical_down": 0}},
  "threats": {"total_attempts": 342, "unique_ips": 89},
  "fail2ban": {"active": true, "total_banned": 12},
  "docker": {"running_containers": 1, "rootless": false},
  "kernel_hardening": {"hardening_percentage": 100.0},
  "recommendations": [...]
}
```

**Privacy**: IPs and hostnames are masked by default (`203.0.***.***`, `srv-ab**`). Disable with `{"mask_data": false}`.

## Configuration (Optional)

Create `.mcp-security.json` to customize:

```json
{
  "checks": {
    "firewall": true,
    "ssh": true,
    "ssl": true,
    "disk": true,
    "cve": true,
    "cis": true,
    "nist": true,
    "pci": true,
    "containers": true,
    "services": true,
    "docker": false,
    "updates": false
  },
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
- [x] SSL certificate checks ✅
- [x] Disk usage monitoring ✅
- [x] Systemd service health ✅
- [x] CVE scanning (basic) ✅
- [x] CIS Benchmark compliance ✅
- [x] NIST 800-53 baseline ✅
- [x] PCI-DSS v4.0 baseline ✅
- [x] Container image scanning ✅
- [ ] Advanced CVE database integration (NVD, OSV)
- [ ] Alert system (email/webhook/telegram)
- [ ] STIG (Security Technical Implementation Guide)
- [ ] ISO 27001 controls mapping

## Contributing

PRs welcome! Fork, create feature branch, add tests, submit PR.

## License

MIT - see [LICENSE](LICENSE)

---

Created by [Girste](https://girste.com) • [Report issues](https://github.com/girste/mcp-cybersec-watchdog/issues)
