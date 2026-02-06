<div align="center">

![Chihuaudit](docs/chihuaudit-cover.png)

[![CI](https://github.com/girste/CHIHUAUDIT/workflows/CI/badge.svg)](https://github.com/girste/CHIHUAUDIT/actions/workflows/ci.yml)
[![Lint](https://github.com/girste/CHIHUAUDIT/workflows/Lint/badge.svg)](https://github.com/girste/CHIHUAUDIT/actions/workflows/lint.yml)
[![CodeQL](https://github.com/girste/CHIHUAUDIT/workflows/CodeQL/badge.svg)](https://github.com/girste/CHIHUAUDIT/actions/workflows/codeql.yml)
[![Trivy](https://github.com/girste/CHIHUAUDIT/workflows/Trivy/badge.svg)](https://github.com/girste/CHIHUAUDIT/actions/workflows/trivy.yml)
[![Snyk](https://github.com/girste/CHIHUAUDIT/workflows/Snyk%20Security/badge.svg)](https://github.com/girste/CHIHUAUDIT/actions/workflows/snyk.yml)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/girste/CHIHUAUDIT/badge)](https://scorecard.dev/viewer/?uri=github.com/girste/CHIHUAUDIT)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11858/badge)](https://www.bestpractices.dev/projects/11858)
[![SLSA](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Go Report Card](https://goreportcard.com/badge/github.com/girste/CHIHUAUDIT)](https://goreportcard.com/report/github.com/girste/CHIHUAUDIT)

</div>

---

## 🎯 What is Chihuaudit?

A portable, single-binary system auditing tool for Linux. Like [Lynis](https://cisofy.com/lynis/) but faster and smarter.

**No configuration needed. No dependencies. Just run.**

```bash
sudo ./chihuaudit audit
```

## ✨ Features

- **🔒 Security**: Firewall, SSH hardening, SSL/TLS, fail2ban, SUID binaries, open ports
- **🚀 Services**: Systemd services, web servers, databases, Docker
- **💻 Resources**: CPU, RAM, disk usage, top processes
- **💾 Storage**: SMART health, inode usage, filesystem errors
- **🗄️ Databases**: PostgreSQL, MySQL, Redis health checks
- **🐳 Docker**: Container status, resource usage, volumes
- **🌐 Network**: DNS resolution, latency, interfaces, connections
- **📦 Backups**: Backup detection and freshness checks
- **📝 Logs**: Error analysis, SSH attempts, service restarts
- **⏰ Monitoring**: Continuous mode with Discord webhook notifications

## 🤖 Claude Skill Alternative

![Chihuaudit Skill](docs/chihu-skill.png)

**Don't want to install anything?** Use the **Claude Skill** version instead!

Execute the same comprehensive system audit directly through Claude (Sonnet, Opus, or Haiku) using native shell commands - no binary installation required.

**Key Benefits**:
- 🚀 **Zero Installation** - Works immediately with sudo access
- 🔄 **Consistent Results** - 1+ year of production use with extremely reliable output
- 📊 **Same Coverage** - All 87 checks, 10 categories, identical methodology
- ⚡ **Fast** - 30-90 second execution time

**Requirements**: Linux with systemd, sudo NOPASSWD configured, Claude with shell access

**Documentation**: [docs/skill/chihuaudit-skill.md](docs/skill/chihuaudit-skill.md)

---

## Webhook Alerts

![Webhook Alerts](docs/chihualerts.png)

Chihuaudit supports **webhook notifications** for real-time monitoring alerts. While optimized for Discord, it works with **any webhook-compatible service** (Slack, Microsoft Teams, Mattermost, custom endpoints, etc.).

<img src="docs/test-screen.png" width="500" alt="Discord Webhook Examples">

*Color-coded alerts: 🟢 Green (healthy), 🟡 Yellow (warnings), 🔴 Red (critical)*

### Setup

```bash
# Generate default config
./bin/chihuaudit init-config

# Edit configuration
nano ~/.chihuaudit/config.json
```

### Configuration

```json
{
  "discord_webhook": "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN",
  "notification_whitelist": {
    "cpu_threshold": 70,
    "memory_threshold": 70,
    "disk_threshold": 85,
    "ignore_changes": ["uptime", "active_connections"]
  }
}
```

### Webhook Compatibility

| Platform | Support |
|----------|---------|
| **Discord** | Native — rich embeds, color-coded alerts, timestamps |
| **Slack** | Works — embeds translate to attachments |
| **Teams** | Works — incoming webhook format |
| **Mattermost** | Works — Slack-compatible webhooks |
| **Custom** | Any service accepting JSON POST |

### Alert Thresholds

**CPU Load**: Trigger when load average exceeds threshold
**Memory Usage**: Alert on RAM usage percentage
**Disk Space**: Warning when disk usage crosses limit
**Ignore List**: Skip notifications for frequently changing metrics

### Monitoring Mode

```bash
# Monitor every 5 minutes with webhook alerts
sudo ./bin/chihuaudit monitor --interval=5m
```

Changes are detected and only significant events trigger notifications, reducing alert fatigue.

---

## Self Hosted Dashboard

![Self Hosted Dashboard](docs/chihucloud.png)

**Chihuaudit Cloud** is a self-hosted web dashboard for collecting and visualizing audits from multiple hosts. Single binary, SQLite database, zero external dependencies.

<!-- TODO: add dashboard screenshot -->

### How It Works

1. **Deploy the dashboard** — single binary, runs anywhere
2. **Register hosts** — each host gets a unique API key
3. **Agents push audits** — configure `cloud_url` + `api_key` in the agent config
4. **Monitor everything** — real-time dashboard with history, alerting, and webhooks

### Features

- **Multi-host overview** — all your servers in one place
- **Audit history** — browse and compare past audits per host
- **Change detection** — automatic diff between consecutive audits
- **Threshold alerts** — CPU, memory, disk with per-host configuration
- **Persistent breach alerts** — webhook notification when thresholds stay exceeded for 48h+
- **Webhook integration** — Discord, Slack, and generic JSON webhooks
- **API key auth** — SHA-256 hashed, shown only once at creation
- **Retention policies** — per-host configurable audit retention
- **Rate limiting** — 60 req/min per API key

### Quick Start

```bash
# Build
go build ./cmd/chihuaudit-cloud
# or
./build.sh cloud

# Run
export JWT_SECRET="your-secret-here"
./chihuaudit-cloud
```

The dashboard listens on `:8091` by default. SQLite database is created automatically.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | *(required)* | Secret for JWT token signing |
| `DATABASE_PATH` | `./chihuaudit-cloud.db` | SQLite database file path |
| `LISTEN_ADDR` | `:8091` | HTTP listen address |

---

<details>
<summary><h2>🚀 Quick Start</h2></summary>

### Build

```bash
make build
# or
./build.sh
```

### Run

```bash
# Single audit
sudo ./bin/chihuaudit audit

# JSON output
sudo ./bin/chihuaudit audit --json

# Continuous monitoring
sudo ./bin/chihuaudit monitor --interval=5m

# Generate config
./bin/chihuaudit init-config
```

</details>

<details>
<summary><h2>📊 Example Output</h2></summary>

### Terminal Output

```
=== CHIHUAUDIT REPORT ===
Timestamp: 2026-02-05 12:38:27
Hostname: server.example.com
OS: Ubuntu 24.04.3 LTS

--- 1. SECURITY ---
Firewall: active (ufw) ✓
SSH: active
SSH Port: 2244
SSH Password Auth: disabled ✓
SSH Root Login: no ✓
External Ports: [443, 80, 2244]
Localhost-Only Ports: [5432, 6379]
SSL Certificates: 5 (all valid)

--- 2. SERVICES ---
Total Running: 31
Failed: 0 ✓
Web: caddy (active)
Database: postgresql (active)

[... 8 more categories ...]

Total Checks: 87
```

</details>

<details>
<summary><h2>🎯 Design Philosophy</h2></summary>

- **Universal**: Works on any Linux distro without configuration
- **Portable**: Single static binary, zero dependencies
- **Safe**: Read-only checks, no system modifications
- **Fast**: Parallel execution, ~1 second for full audit
- **Simple**: Minimal code, maximum clarity
- **Automated**: Perfect for CI/CD and monitoring

</details>

## 📖 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Development Log](docs/DEVELOPMENT.md)
- [Contributing Guidelines](CONTRIBUTING.md)

<details>
<summary><h2>🏗️ Architecture</h2></summary>

```
chihuaudit/
├── main.go                # CLI entry point (agent)
├── checks/                # 10 audit categories
│   ├── security.go        # Firewall, SSH, SSL, ports
│   ├── services.go        # Systemd, web, DB servers
│   ├── resources.go       # CPU, RAM, disk
│   └── ...
├── detect/                # OS/tool detection
├── notify/                # Discord webhooks
├── report/                # Text/JSON formatters
├── state/                 # Change tracking
├── cloud/                 # Cloud dashboard packages
│   ├── models/            # SQLite database layer
│   ├── handlers/          # HTTP API handlers
│   ├── alerting/          # Change detection & webhooks
│   └── middleware/        # JWT authentication
└── cmd/chihuaudit-cloud/  # Cloud dashboard entry point
    ├── migrations/        # SQLite schema
    └── static/            # Web frontend
```

</details>

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Keep code:
- **Simple**: Minimal, readable, maintainable
- **Portable**: Detection-based, no hardcoded paths
- **Safe**: No shell injection, no user input in commands
- **Consistent**: Follow existing patterns

## 📜 License

MIT License - see [LICENSE](LICENSE) for details

---

<div align="center">

**Made with ❤️ for sysadmins everywhere**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>
