# Webhook Notifications

> **Note:** All data shown below is fictional and for demonstration purposes only.

Discord and Slack integration for security alerts.

## Configuration

```bash
# Configure webhook
configure_webhook --url "https://discord.com/api/webhooks/..." --platform discord

# Test webhook
test_webhook
```

## Discord Alert Example

### Critical Alert (Red)

![Discord Critical Alert](../images/discord-critical.png)

**Text format:**
```
🚨 SECURITY ALERT - production-web-01

Status: 🔴 CRITICAL
Score: 45/100 (Grade: F)
Time: 2026-01-25 18:42:13 UTC

⚠️ CRITICAL ISSUES:
• Firewall disabled (UFW inactive)
• SSH root login enabled
• 3 unpatched critical CVEs detected

💡 RECOMMENDATIONS:
1. Enable firewall immediately: sudo ufw enable
2. Disable root SSH: PermitRootLogin no
3. Apply security updates: sudo apt upgrade

Full report: https://monitoring.example.com/reports/2026-01-25-184213
```

---

### Warning Alert (Yellow)

![Discord Warning Alert](../images/discord-warning.png)

**Text format:**
```
⚠️ Security Warning - production-web-01

Status: 🟡 WARNINGS
Score: 72/100 (Grade: C)

Issues detected:
• Docker daemon exposed without TLS
• MySQL listening on 0.0.0.0:3306
• Backup overdue (8 days old)

View details: https://monitoring.example.com/reports/latest
```

---

### Success Report (Green)

![Discord Success](../images/discord-success.png)

**Text format:**
```
✅ Security Check Passed - production-web-01

Status: 🟢 GOOD
Score: 100/100 (Grade: A)

All security checks passed!
• Firewall active
• SSH hardened
• Fail2ban protecting
• System fully updated
```

---

## Slack Alert Example

### Critical Alert

![Slack Critical Alert](../images/slack-critical.png)

```json
{
  "attachments": [
    {
      "color": "danger",
      "title": "🚨 SECURITY ALERT - production-web-01",
      "fields": [
        {
          "title": "Status",
          "value": "🔴 CRITICAL",
          "short": true
        },
        {
          "title": "Score",
          "value": "45/100 (F)",
          "short": true
        },
        {
          "title": "Critical Issues",
          "value": "• Firewall disabled\n• SSH root login enabled\n• 3 unpatched CVEs",
          "short": false
        }
      ],
      "footer": "Chihuaudit",
      "ts": 1706201533
    }
  ]
}
```

---

## Custom Webhook

Generic webhook format for any platform:

```json
{
  "timestamp": "2026-01-25T18:42:13Z",
  "hostname": "production-web-01",
  "status": "red",
  "score": 45,
  "grade": "F",
  "issues": [
    {
      "severity": "critical",
      "category": "firewall",
      "message": "Firewall disabled (UFW inactive)"
    },
    {
      "severity": "high",
      "category": "ssh",
      "message": "SSH root login enabled"
    }
  ],
  "report_url": "https://monitoring.example.com/reports/2026-01-25-184213"
}
```

---

## Alert Conditions

Configure when to send alerts:

```bash
# Alert only on issues
sudo ./bin/chihuaudit audit --webhook --on-issues

# Alert always (for scheduled reports)
sudo ./bin/chihuaudit audit --webhook

# Alert only on critical/high severity
sudo ./bin/chihuaudit audit --webhook --severity=high
```

---

> **Note:** Screenshot placeholders above. Add actual Discord/Slack screenshots to `docs/images/` directory.
