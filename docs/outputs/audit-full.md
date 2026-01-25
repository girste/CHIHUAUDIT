# Security Audit - Full Output Example

Complete system security analysis with all checks.

```
═══════════════════════════════════════════════════════════════
  🟡  SECURITY REPORT  -  production-web-01
═══════════════════════════════════════════════════════════════

  Status: 🟡 WARNINGS - Some security issues detected
  Score:  72/100 (Grade: C)
  Time:   2026-01-25T14:30:45Z

───────────────────────────────────────────────────────────────
  ✅ WHAT'S WORKING WELL
───────────────────────────────────────────────────────────────
  • Firewall is active and protecting the system
  • Root SSH login is disabled
  • SSH password authentication disabled (key-only)
  • Fail2ban is active and blocking attacks
  • AppArmor is enforcing security policies
  • System updates are current
  • Kernel hardening enabled
  • SSL certificates are valid

───────────────────────────────────────────────────────────────
  ⚠️  ISSUES REQUIRING ATTENTION
───────────────────────────────────────────────────────────────
  🔴 [HIGH] Docker daemon exposed without TLS authentication
  ⚠️ [MEDIUM] MySQL listening on 0.0.0.0:3306 (internet-facing)
  ⚠️ [MEDIUM] Last backup is 8 days old
  ⚠️ [LOW] 3 Docker containers running with --privileged flag

───────────────────────────────────────────────────────────────
  💡 RECOMMENDATIONS
───────────────────────────────────────────────────────────────
  1. Enable Docker TLS authentication immediately
  2. Bind MySQL to 127.0.0.1 or use firewall rules
  3. Review backup automation schedule
  4. Audit privileged containers for security risks

═══════════════════════════════════════════════════════════════
```

## JSON Format

```json
{
  "timestamp": "2026-01-25T14:30:45Z",
  "hostname": "production-web-01",
  "traffic_light": {
    "status": "yellow",
    "emoji": "🟡",
    "label": "WARNINGS - Some security issues detected"
  },
  "score": {
    "value": 72,
    "grade": "C",
    "max_score": 100
  },
  "positives": [
    "Firewall is active and protecting the system",
    "Root SSH login is disabled",
    "SSH password authentication disabled (key-only)",
    "Fail2ban is active and blocking attacks",
    "AppArmor is enforcing security policies",
    "System updates are current",
    "Kernel hardening enabled",
    "SSL certificates are valid"
  ],
  "negatives": [
    {
      "severity": "high",
      "category": "docker",
      "message": "Docker daemon exposed without TLS authentication"
    },
    {
      "severity": "medium",
      "category": "network",
      "message": "MySQL listening on 0.0.0.0:3306 (internet-facing)"
    },
    {
      "severity": "medium",
      "category": "backup",
      "message": "Last backup is 8 days old"
    },
    {
      "severity": "low",
      "category": "docker",
      "message": "3 Docker containers running with --privileged flag"
    }
  ]
}
```
