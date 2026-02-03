# Chihuaudit

![Chihuaudit Logo](docs/images/chihuaudit_cover.png)

<!-- Build & CI -->
[![CI](https://github.com/girste/CHIHUAUDIT/actions/workflows/ci.yml/badge.svg)](https://github.com/girste/CHIHUAUDIT/actions)
[![Lint](https://github.com/girste/CHIHUAUDIT/actions/workflows/lint.yml/badge.svg)](https://github.com/girste/CHIHUAUDIT/actions/workflows/lint.yml)
[![Docker](https://github.com/girste/CHIHUAUDIT/actions/workflows/docker.yml/badge.svg)](https://github.com/girste/CHIHUAUDIT/actions/workflows/docker.yml)
[![Release](https://github.com/girste/CHIHUAUDIT/actions/workflows/release.yml/badge.svg)](https://github.com/girste/CHIHUAUDIT/releases)

<!-- Security -->
[![CodeQL](https://github.com/girste/CHIHUAUDIT/actions/workflows/codeql.yml/badge.svg)](https://github.com/girste/CHIHUAUDIT/security/code-scanning)
[![Trivy](https://github.com/girste/CHIHUAUDIT/actions/workflows/trivy.yml/badge.svg)](https://github.com/girste/CHIHUAUDIT/security)
[![Snyk](https://github.com/girste/CHIHUAUDIT/actions/workflows/snyk.yml/badge.svg)](https://github.com/girste/CHIHUAUDIT/security)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/girste/CHIHUAUDIT/badge)](https://securityscorecards.dev/viewer/?uri=github.com/girste/CHIHUAUDIT)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

<!-- Code Quality -->
[![Codecov](https://img.shields.io/codecov/c/github/girste/CHIHUAUDIT)](https://codecov.io/gh/girste/CHIHUAUDIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/girste/chihuaudit)](https://goreportcard.com/report/github.com/girste/chihuaudit)

<!-- Version & License -->
[![Go Version](https://img.shields.io/github/go-mod/go-version/girste/chihuaudit)](https://go.dev/)
[![Latest Release](https://img.shields.io/github/v/release/girste/chihuaudit)](https://github.com/girste/chihuaudit/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**System Configuration Drift Detection for Linux Servers**

Monitor server configuration changes, detect deviations from baseline, and get AI-powered insights.

## What It Does

Chihuaudit continuously monitors your Linux server's system configuration and alerts you when changes occur:

- **Firewall rules** (ufw/iptables/nftables)
- **SSH configuration** (sshd_config changes)
- **Open ports and services** (systemd, network listeners)
- **System users and groups**
- **Critical file permissions** (/etc/passwd, /etc/shadow, etc.)
- **Kernel parameters** (sysctl)
- **Docker containers and security**
- **Cron jobs and scheduled tasks**
- **Security tools** (fail2ban, AppArmor/SELinux)

### Key Features

✅ **Signed Baselines** - Cryptographically signed baseline to prevent tampering  
✅ **Drift Detection** - Automated comparison against known-good state  
✅ **Alert Codes** - Each alert has a unique code (e.g., `FW-001`, `SSH-003`) for tracking and whitelisting  
✅ **AI Insights** - On-demand explanations of what changed and why it matters  
✅ **Discord/Slack Webhooks** - Real-time notifications  
✅ **Git-Friendly Output** - YAML/JSON format for version control integration  
✅ **Whitelist System** - Suppress known-safe changes  

## Tools

**`security_audit`** — Complete system security analysis  
**`start_monitoring`** / **`stop_monitoring`** / **`monitoring_status`** — Continuous monitoring daemon  
**`analyze_anomaly`** — AI anomaly detection analysis  
**`cleanup_old_logs`** — Log rotation  
**`configure_webhook`** / **`test_webhook`** / **`get_notification_config`** — Discord/Slack/custom webhooks  
**`manage_whitelist`** — AI-driven whitelist for false positives  

## Alert System

Real-time security notifications with severity-based anomaly detection. Each alert includes:

- **Unique code** (e.g., `FW-001`, `SSH-003`) for tracking
- **Severity level** (critical, high, medium, low)
- **Category** (firewall, ssh, services, etc.)
- **Detailed message** explaining what changed

**Examples:** [Discord Alert](docs/images/screen-discord.png) | [Full Audit Output](docs/outputs/)

## Installation

**Docker (recommended):**
```bash
docker pull steuuu/chihuaudit:latest
```

**GitHub Container Registry:**
```bash
docker pull ghcr.io/girste/chihuaudit:latest
```

**Binary release:**
```bash
curl -sSfL https://github.com/girste/CHIHUAUDIT/releases/latest/download/chihuaudit_linux_amd64 -o chihuaudit
chmod +x chihuaudit
./chihuaudit audit
```

**Latest release:** [v0.0.1 Teacup](https://github.com/girste/CHIHUAUDIT/releases/latest)

## Security

**Reporting vulnerabilities:** See [SECURITY.md](.github/SECURITY.md)  
**Supported versions:** v0.0.1+  
**SLSA Level 3** supply chain security  

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code standards, and PR guidelines.

---

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**MIT License** — Free and open source  
Contact: **me@girste.com**

</div>
