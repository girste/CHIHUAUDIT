# 🐕 MCP Cybersec Watchdog

**Complete Linux security audit in 30 seconds** via Claude MCP. Zero configuration required.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/test.yml/badge.svg)](https://github.com/girste/mcp-cybersec-watchdog/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/girste/mcp-cybersec-watchdog/branch/main/graph/badge.svg)](https://codecov.io/gh/girste/mcp-cybersec-watchdog)
[![PyPI](https://img.shields.io/badge/PyPI-mcp--cybersec--watchdog-blue)](https://pypi.org/project/mcp-cybersec-watchdog/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Features

**One-Time Audit (23 analyzers, 89 CIS controls)**
- Firewall, SSH, fail2ban, Docker, SSL certificates
- CVE scanning, container image scanning (trivy)
- Compliance: CIS Benchmark, NIST 800-53, PCI-DSS v4.0
- Kernel hardening, MAC (AppArmor/SELinux), rootkit detection
- Multi-level scoring (personal/business/corporate/military)

**Live Monitoring (Beta)**
- Background daemon with anomaly detection
- Alerts on firewall changes, new ports, attack spikes, compliance drift
- AI analysis only when needed (token-efficient)

## Quick Start

```bash
# Install
pip install mcp-cybersec-watchdog

# Setup passwordless sudo (required)
bash <(curl -s https://raw.githubusercontent.com/girste/mcp-cybersec-watchdog/main/setup-sudo.sh)

# Run audit
mcp-watchdog test

# Start monitoring (checks every hour)
mcp-watchdog monitor
```

## Claude Desktop Integration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cybersec-watchdog": {
      "command": "/path/to/venv/bin/mcp-watchdog"
    }
  }
}
```

**Example prompts:**
```
Run a security audit on this server
Start monitoring with 30 minute intervals
Show monitoring status
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `security_audit` | Comprehensive one-time audit |
| `start_monitoring` | Start background monitoring |
| `stop_monitoring` | Stop daemon |
| `monitoring_status` | Check status and recent bulletins |
| `analyze_anomaly` | AI analysis of detected anomalies |

## Output Example

```json
{
  "analysis": {
    "overall_status": "GOOD",
    "profile_scores": {
      "personal": 93.3,
      "business": 88.8,
      "corporate": 83.8,
      "military": 82.2
    }
  },
  "firewall": {"type": "ufw", "active": true, "open_ports": [80, 443, 22]},
  "cis_benchmark": {"compliance_percentage": 78.3},
  "nist_800_53": {"compliance_percentage": 80.0},
  "pci_dss": {"compliance_percentage": 100.0},
  "threats": {"total_attempts": 342, "unique_ips": 89},
  "recommendations": [...]
}
```

**Privacy**: IPs/hostnames masked by default. Disable with `{"mask_data": false}`.

## Configuration (Optional)

Create `.mcp-security.json` to customize checks:

```json
{
  "checks": {
    "firewall": true,
    "ssh": true,
    "cis": true,
    "docker": false
  },
  "threat_analysis_days": 14
}
```

## Development

```bash
git clone https://github.com/girste/mcp-cybersec-watchdog
cd mcp-cybersec-watchdog
pip install -e ".[dev]"
pytest tests/ -v
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Report vulnerabilities via [SECURITY.md](SECURITY.md).

## License

MIT - see [LICENSE](LICENSE)

---

Created by [Girste](https://girste.com) • [Issues](https://github.com/girste/mcp-cybersec-watchdog/issues)
