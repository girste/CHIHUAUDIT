# Live Monitoring Guide

## Overview

MCP Cybersec Watchdog now includes **continuous security monitoring** with intelligent anomaly detection.

### Key Features

- **Baseline Tracking**: First run establishes security baseline
- **Anomaly Detection**: Detects 20+ types of security changes
- **Token-Efficient AI**: AI analysis triggered ONLY when anomalies detected
- **Human-Readable Bulletins**: Simple status reports every check
- **Low Resource Usage**: ~10-20MB RAM, minimal CPU

## Quick Start

### 1. One-Time Check

```bash
# Test monitoring (creates baseline on first run)
mcp-watchdog monitor-once

# Run again to see bulletin
mcp-watchdog monitor-once
```

**Output**:
```
======================================================================
MCP CYBERSEC WATCHDOG - Security Bulletin
Generated: 2025-12-28 15:30:13 UTC
======================================================================

Status: ✓ ALL OK
Monitoring since: 0.0 hours ago

No anomalies detected - all systems nominal

CURRENT STATE:
----------------------------------------------------------------------
Overall: GOOD
Issues: 0 critical, 0 high priority
Good practices: 8
Firewall: ACTIVE (ufw) - 8 rules, 3 open ports
SSH: Port 22 - Root=no, Password=no
Threats: 0 failed login attempts from 0 IPs (7 days)
Fail2ban: ACTIVE - 0 IPs banned
Docker: 1 containers running

======================================================================
```

### 2. Continuous Monitoring

```bash
# Start monitoring (default: every 1 hour)
mcp-watchdog monitor

# Custom interval (every 30 minutes)
mcp-watchdog monitor --interval 1800

# Custom log directory
mcp-watchdog monitor --log-dir /var/log/security-monitor
```

**Behavior**:
- Check #1: Creates baseline, no anomalies
- Check #2+: Compare vs baseline, detect changes
- Every check: Write bulletin to log file
- If anomalies: Write detailed JSON for AI analysis

## Anomaly Detection

### What Gets Detected

**Critical Severity**:
- Firewall disabled
- SSH root login enabled
- New privileged Docker containers

**High Severity**:
- New ports opened
- SSH password auth enabled
- Fail2ban disabled
- Attack volume spike (3x increase)

**Medium Severity**:
- Firewall rules changed significantly
- SSH port changed
- New network services
- Attack IP count increased (50%+)
- Critical security updates available

**Low Severity**:
- Many new Docker containers
- Configuration drift

### Example: Port Opening Detection

```bash
# Baseline: Ports 22, 80, 443 open
# Someone opens MySQL port 3306

# Next check detects:
[HIGH] firewall: New ports opened: [3306]

# Creates anomaly file: /var/log/mcp-watchdog/anomaly_20251228_150000.json
```

## AI Analysis (Token-Efficient)

The tool uses **two-tier approach** to save tokens:

### Tier 1: Rule-Based Detection (No AI, No Tokens)
- Every check runs lightweight comparison
- Detects anomalies using predefined rules
- Generates simple bulletins

### Tier 2: AI Analysis (Only When Needed)
- Triggered ONLY when anomalies detected
- Uses MCP tool `analyze_anomaly`
- Provides deep contextual insights

**Example workflow**:
```bash
# Monitoring running...

# Hour 1-10: All OK
✓ ALL OK → Bulletin written (no AI)
✓ ALL OK → Bulletin written (no AI)
# ... 0 tokens used

# Hour 11: Anomaly detected!
⚠️  HIGH SEVERITY ANOMALY DETECTED
Run AI analysis: Use MCP tool 'analyze_anomaly' with file /var/log/mcp-watchdog/anomaly_20251228_110000.json

# Now you can:
# 1. Read the bulletin yourself (human-readable)
# 2. Ask Claude to analyze it (AI insights)
# 3. Ignore if expected change
```

### Using AI Analysis via MCP

From Claude Desktop:
```
Analyze the security anomaly in /var/log/mcp-watchdog/anomaly_20251228_110000.json
```

Claude will:
- Read the anomaly details
- Analyze what changed and why
- Assess severity and risk
- Recommend specific actions
- Provide commands to fix issues

## Log Files

Monitoring creates these files:

```
/var/log/mcp-watchdog/
├── bulletin_20251228_100000.txt   # Hourly status reports
├── bulletin_20251228_110000.txt
├── bulletin_20251228_120000.txt
└── anomaly_20251228_110000.json   # Only when anomalies detected
```

**Bulletins**: Human-readable text files (300-500 bytes)
**Anomaly reports**: Detailed JSON for AI analysis (~5-10KB)

## Baseline Management

The baseline is stored at `/var/lib/mcp-watchdog/baseline.json` (or `/tmp/mcp-watchdog-{uid}/baseline.json` for non-root users).

### Reset Baseline

If you made intentional changes and want to establish new baseline:

```bash
# Delete baseline file
rm /var/lib/mcp-watchdog/baseline.json

# Next monitor run creates fresh baseline
mcp-watchdog monitor-once
```

## Production Deployment

### As Systemd Service

```bash
# Create service file
sudo nano /etc/systemd/system/mcp-watchdog.service
```

```ini
[Unit]
Description=MCP Cybersec Watchdog Monitoring
After=network.target

[Service]
Type=simple
User=root
ExecStart=/path/to/venv/bin/mcp-watchdog monitor --interval 3600
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl enable mcp-watchdog
sudo systemctl start mcp-watchdog

# Check status
sudo systemctl status mcp-watchdog

# View logs
sudo journalctl -u mcp-watchdog -f
```

### As Cron Job

```bash
# Every hour
0 * * * * /path/to/venv/bin/mcp-watchdog monitor-once >> /var/log/mcp-watchdog/cron.log 2>&1
```

## Resource Usage

**Memory**: ~10-20MB (Python process + audit data)
**CPU**: <1% (spikes to ~5-10% during check, then idle)
**Disk**: ~1KB per bulletin, ~10KB per anomaly report
**Network**: None (local checks only)

**For 1-hour interval**:
- 24 checks/day
- ~24KB bulletins/day
- Variable anomaly reports (only when detected)

## FAQ

**Q: How often should I check?**
A: Default 1 hour is good for most servers. High-security: 15-30 minutes. Low-traffic: 2-4 hours.

**Q: Will it alert me immediately?**
A: Currently no. It writes to log files. For immediate alerts, integrate with webhook/SIEM (future feature).

**Q: Does it use tokens when nothing happens?**
A: No! Rule-based detection is free. AI analysis only when anomalies found.

**Q: What if I get false positives?**
A: Reset baseline after making intentional changes.

**Q: Can I run without sudo?**
A: Yes, but some checks will be limited (firewall status, fail2ban, etc). Uses temp directories automatically.

**Q: How do I stop monitoring?**
A: Press Ctrl+C if running in foreground, or `systemctl stop mcp-watchdog` if systemd service.

## Example Scenarios

### Scenario 1: Brute Force Attack Spike

```
Status: ⚠ HIGH SEVERITY ANOMALY DETECTED

[HIGH] threats: Attack volume spike: 45 → 1,203 attempts

# AI analysis reveals:
# - 95% from China/Russia IP blocks
# - Targeting SSH default port
# - Recommendations:
#   1. Enable fail2ban (auto-ban after 3 attempts)
#   2. Change SSH port to non-standard
#   3. Disable password auth, use keys only
```

### Scenario 2: Unauthorized Port Opening

```
Status: ⚠ HIGH SEVERITY ANOMALY DETECTED

[HIGH] firewall: New ports opened: [3306]
[MEDIUM] services: New services listening: ports [3306]

# AI analysis reveals:
# - MySQL now exposed to internet
# - bind-address = 0.0.0.0 detected
# - Recommendations:
#   1. Close port 3306 in firewall
#   2. Set bind-address=127.0.0.1 in my.cnf
#   3. Use SSH tunnel for remote access
```

### Scenario 3: Configuration Drift

```
Status: ⚠ ANOMALIES DETECTED

[MEDIUM] ssh: SSH port changed: 22 → 2222
[LOW] firewall: Firewall rules changed: 8 → 9

# Expected change after hardening
# Reset baseline to acknowledge
```

## Advanced Usage

### Integration with Monitoring Stack

```bash
# Export to Prometheus format (future)
mcp-watchdog monitor --format prometheus

# Send to SIEM (future)
mcp-watchdog monitor --webhook https://siem.example.com/events

# Log to syslog (future)
mcp-watchdog monitor --syslog
```

### Custom Alerting

```bash
# Simple email alert on anomaly
mcp-watchdog monitor-once | grep "ANOMALY DETECTED" && \
  mail -s "Security Anomaly" admin@example.com < /var/log/mcp-watchdog/bulletin_*.txt
```

## Roadmap

Future enhancements:
- [ ] Webhook alerts (Slack, Discord, PagerDuty)
- [ ] SIEM integration (Splunk, ELK, Datadog)
- [ ] Event-driven monitoring (inotify on config files)
- [ ] Prometheus metrics export
- [ ] Web dashboard
- [ ] Email notifications
- [ ] Anomaly severity tuning
- [ ] Custom alert rules
