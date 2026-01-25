# Output Examples

Real-world output examples from MCP Cybersec Watchdog.

## Available Examples

### Core Audits
- **[Security Audit (Full)](audit-full.md)** - Complete system security analysis with traffic light status
- **[CIS Benchmark](cis-benchmark.md)** - Ubuntu 22.04 compliance check (60+ controls)

### Specialized Scans
- **[Network Security](network-scan.md)** - Listening services, firewall rules, kernel hardening

### Monitoring
- **[Monitoring Daemon](monitoring-daemon.md)** - Continuous monitoring with anomaly detection

### Notifications
- **[Webhook Alerts](webhook-notifications.md)** - Discord/Slack integration examples

---

## Quick Reference

| Tool | Command | Output Format |
|------|---------|---------------|
| Full Audit | `sudo ./bin/mcp-watchdog audit` | Text (traffic light) |
| JSON Output | `sudo ./bin/mcp-watchdog audit --format=json` | JSON |
| CIS Benchmark | `sudo ./bin/mcp-watchdog audit --cis` | Text (compliance) |
| Network Scan | MCP: `scan_network_security` | Structured report |
| Monitoring Status | `sudo ./bin/mcp-watchdog monitor-status` | Daemon stats |
| Webhook Test | MCP: `test_webhook` | Live notification |

---

## Adding Your Own Examples

To add screenshots (Discord/Slack alerts):

1. Place images in `docs/images/`
2. Reference in markdown: `![Alt text](../images/filename.png)`
3. Keep images under 500KB for fast loading
