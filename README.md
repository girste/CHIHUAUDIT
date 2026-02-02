# Chihuaudit

![Chihuaudit Logo](docs/images/chihuaudit_cover.png)

[![CI](https://github.com/girste/CHIHUAUDIT/actions/workflows/ci.yml/badge.svg)](https://github.com/girste/CHIHUAUDIT/actions)
[![Lint](https://github.com/girste/CHIHUAUDIT/actions/workflows/lint.yml/badge.svg)](https://github.com/girste/CHIHUAUDIT/actions/workflows/lint.yml)
[![CodeQL](https://github.com/girste/CHIHUAUDIT/actions/workflows/codeql.yml/badge.svg)](https://github.com/girste/CHIHUAUDIT/security/code-scanning)
[![Trivy](https://github.com/girste/CHIHUAUDIT/actions/workflows/trivy.yml/badge.svg)](https://github.com/girste/CHIHUAUDIT/actions/workflows/trivy.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11858/badge)](https://www.bestpractices.dev/projects/11858)
[![Mentioned in Awesome](https://awesome.re/mentioned-badge.svg)](https://github.com/punkpeye/awesome-mcp-servers)

<div align="center">

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/girste/CHIHUAUDIT/badge)](https://securityscorecards.dev/viewer/?uri=github.com/girste/CHIHUAUDIT)
[![Docker Pulls](https://img.shields.io/docker/pulls/steuuu/chihuaudit)](https://hub.docker.com/r/steuuu/chihuaudit)

[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Go Report Card](https://goreportcard.com/badge/github.com/girste/chihuaudit)](https://goreportcard.com/report/github.com/girste/chihuaudit)

</div>

Single full system checkup or ontinuous monitoring with anomaly detection, Discord/Slack webhooks.

## Quick Start

**Download binary:**
```bash
curl -sSfL https://github.com/girste/CHIHUAUDIT/releases/latest/download/chihuaudit_linux_amd64 -o chihuaudit
chmod +x chihuaudit
./chihuaudit audit
```

**Pull Docker image:**
```bash
docker pull steuuu/chihuaudit:latest
```

## Tools

**`security_audit`** — Complete system security analysis  
**`cis_audit`** — CIS Benchmark compliance check  
**`scan_app_security`** — Ports, processes, containers  
**`scan_network_security`** — Network & firewall rules  
**`scan_database_security`** — Database exposure & hardening  
**`scan_waf_cdn`** — WAF/CDN detection & SSL/TLS  
**`verify_backup_config`** — Backup integrity verification  
**`check_vulnerability_intel`** — CVE database lookup (EU Vulnerability Database)  
**`start_monitoring`** / **`stop_monitoring`** / **`monitoring_status`** — Continuous monitoring daemon  
**`analyze_anomaly`** — AI anomaly detection analysis  
**`cleanup_old_logs`** — Log rotation  
**`configure_webhook`** / **`test_webhook`** / **`get_notification_config`** — Discord/Slack/custom webhooks  
**`manage_whitelist`** — AI-driven whitelist for false positives  

## Alert System

Real-time security notifications with severity-based anomaly detection. Detects configuration changes, port exposure, failed services, and security degradation.

**Examples:** [Discord Alert](docs/images/screen-discord.png) | [Full Audit Output](docs/outputs/)

## Docker Usage

**Binary on host (recommended):**
```bash
docker pull steuuu/chihuaudit:latest
```

**GitHub Container Registry:**
```bash
docker pull ghcr.io/girste/chihuaudit:latest
```

Full configuration in [Docker Documentation](DOCKER_RELEASE.md).

## Security

**Reporting vulnerabilities:** See [SECURITY.md](.github/SECURITY.md)  
**Supported versions:** v0.0.1+  
**SLSA Level 3** supply chain security  

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code standards, and PR guidelines.

---

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
