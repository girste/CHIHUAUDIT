# MCP Cybersec Watchdog - API Reference

Complete reference for the command-line interface and MCP tools.

## CLI Commands

### `audit`

Run a complete security audit with standardized output.

**Usage:**
```bash
mcp-watchdog audit [options]
```

**Options:**
- `--format <json|text|summary>` - Output format (default: text)
- `--ai-mode` - Enable AI-friendly output format
- `--output <file>` - Write output to file

**Exit Codes:**
- `0` - No critical issues (score >= 80)
- `1` - Critical issues found (score < 50)
- `2` - High priority issues (score 50-79)

**Example:**
```bash
sudo ./mcp-watchdog audit --format json > audit-report.json
```

---

### `monitor`

Start continuous security monitoring daemon.

**Usage:**
```bash
mcp-watchdog monitor [options]
```

**Options:**
- `--interval <seconds>` - Check interval (default: 300)
- `--log-dir <path>` - Log directory (default: /var/log/mcp-watchdog)
- `--baseline <file>` - Baseline comparison file

**Example:**
```bash
sudo ./mcp-watchdog monitor --interval 600
```

---

### `monitor-status`

Check the status of the monitoring daemon.

**Usage:**
```bash
mcp-watchdog monitor-status
```

**Output:** JSON with daemon status, uptime, last check time, anomalies detected.

---

## MCP Tools

MCP tools are called by AI assistants (Claude, etc.) via the Model Context Protocol.

### `security_audit`

Complete system security analysis.

**Input:** None

**Output:**
```json
{
  "timestamp": "2026-01-30T17:00:00Z",
  "hostname": "server-01",
  "score": 85,
  "status": "green|yellow|red",
  "firewall": {...},
  "ssh": {...},
  "fail2ban": {...},
  "analysis": {...}
}
```

---

### `cis_audit`

CIS Benchmark Ubuntu 22.04 compliance check.

**Input:** None

**Output:**
```json
{
  "total_checks": 60,
  "passed": 55,
  "failed": 5,
  "compliance_percentage": 91.7,
  "checks": [...]
}
```

---

### `check_vulnerability_intel`

Query CVE database (EU Vulnerability Database, CISA KEV, NVD).

**Input:**
```json
{
  "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"],
  "limit": 20
}
```

**Output:**
```json
{
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-1234",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "description": "...",
      "recommendation": "..."
    }
  ]
}
```

---

### `start_monitoring` / `stop_monitoring`

Control the monitoring daemon.

**Input:**
```json
{
  "interval": 300,
  "log_dir": "/var/log/mcp-watchdog"
}
```

**Output:**
```json
{
  "status": "started|stopped",
  "pid": 12345
}
```

---

### `manage_whitelist`

AI-driven whitelist management for false positives.

**Input:**
```json
{
  "action": "add",
  "whitelist_entry": {
    "port": 5432,
    "bind": "127.0.0.1",
    "service": "PostgreSQL",
    "reason": "Internal database"
  }
}
```

**Output:**
```json
{
  "success": true,
  "message": "Entry added to whitelist"
}
```

---

### `configure_webhook`

Configure Discord/Slack/custom webhook notifications.

**Input:**
```json
{
  "provider": "discord|slack|custom",
  "webhook_url": "https://...",
  "username": "Security Bot",
  "notify_on": ["critical", "high"]
}
```

**Output:**
```json
{
  "success": true,
  "config_saved": true
}
```

---

## Configuration Files

### `.mcp-watchdog.yaml`

Main configuration file (optional).

```yaml
# Notification settings
notifications:
  enabled: true
  discord:
    webhook_url: "https://..."
    username: "Security Bot"

# Monitoring settings
monitoring:
  interval: 300
  log_dir: /var/log/mcp-watchdog
```

---

### `.mcp-watchdog-whitelist.yaml`

Whitelist for false positives (AI-managed).

```yaml
version: "1.0"
services:
  - port: 5432
    bind: "127.0.0.1"
    service: "PostgreSQL"
    reason: "Internal database"

network:
  allowedWildcardPorts: [80, 443]

cis:
  exceptions:
    - id: "3.2.2"
      reason: "Docker requires IP forwarding"

thresholds:
  memory:
    ram_percent: 95.0
    swap_percent: 30.0
```

---

## Return Codes

All CLI commands follow standard Unix exit codes:

- `0` - Success
- `1` - General error
- `2` - Warning (non-critical issues)
- `3` - Configuration error

## Environment Variables

- `MCP_WATCHDOG_CONFIG` - Path to config file
- `MCP_WATCHDOG_LOG_LEVEL` - Logging level (debug|info|warn|error)

## Notes

- All commands requiring system information need `sudo`
- MCP tools are called automatically by AI assistants
- Configuration files are optional (sensible defaults provided)

For more examples, see: https://github.com/girste/mcp-cybersec-watchdog/tree/main/docs/outputs
