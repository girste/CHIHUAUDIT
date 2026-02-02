![Chihuaudit](https://raw.githubusercontent.com/girste/CHIHUAUDIT/main/docs/images/chihuaudit_cover.png)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/girste/CHIHUAUDIT/badge)](https://securityscorecards.dev/viewer/?uri=github.com/girste/CHIHUAUDIT)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![CI](https://github.com/girste/CHIHUAUDIT/actions/workflows/ci.yml/badge.svg)](https://github.com/girste/CHIHUAUDIT/actions)
[![Docker Pulls](https://img.shields.io/docker/pulls/steuuu/chihuaudit)](https://hub.docker.com/r/steuuu/chihuaudit)

**AI-powered Linux security auditing tool.** Single 16MB container, zero dependencies.

Continuous monitoring with anomaly detection, Discord/Slack webhooks, and AI-driven whitelisting for false positive elimination.

---

## Quick Start

### Pull Image

```bash
docker pull steuuu/chihuaudit:latest
```

### Run Security Audit

```bash
docker run --rm \
  --network host --pid host \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  --cap-drop ALL --cap-add NET_RAW --cap-add DAC_READ_SEARCH \
  --security-opt no-new-privileges:true --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  steuuu/chihuaudit:latest audit
```

### Use as MCP Server (Claude Desktop)

**Docker Compose (recommended):**

```yaml
services:
  chihuaudit:
    image: steuuu/chihuaudit:latest
    network_mode: host
    pid: host
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /etc:/host/etc:ro
      - /var:/host/var:ro
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
      - DAC_READ_SEARCH
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=100m
    stdin_open: true
```

**Claude Desktop config** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "chihuaudit": {
      "command": "docker",
      "args": ["compose", "run", "--rm", "chihuaudit"]
    }
  }
}
```

## MCP Tools

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

## Features

- 🔍 **Complete System Audit** - Firewall, SSH, fail2ban, kernel hardening, SSL, services
- 🤖 **AI-Powered Whitelisting** - Automatic false positive elimination  
- 📊 **Continuous Monitoring** - Anomaly detection with Discord/Slack webhooks
- 🔒 **Security First** - Read-only container, minimal capabilities
- 📦 **Zero Dependencies** - Single 16MB image, works everywhere
- 🏆 **Production Ready** - SLSA Level 3, OpenSSF compliant

## Continuous Monitoring

```bash
docker run -d --name chihuaudit-monitor \
  --restart unless-stopped \
  --network host --pid host \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  -v /var:/host/var:ro \
  -v $(pwd)/config:/config:rw \
  -v $(pwd)/logs:/logs:rw \
  --cap-drop ALL --cap-add NET_RAW --cap-add DAC_READ_SEARCH \
  --security-opt no-new-privileges:true --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  -e MCP_CONFIG_DIR=/config \
  steuuu/chihuaudit:latest monitor --interval 3600 --log-dir /logs
```

## Configuration

Create `.chihuaudit.yaml` for webhooks and whitelisting:

```yaml
notify:
  discord:
    - webhook: "https://discord.com/api/webhooks/YOUR_WEBHOOK"
      severity: medium
```

Mount it:
```bash
docker run --rm \
  -v /path/to/.chihuaudit.yaml:/config/.chihuaudit.yaml:ro \
  -e MCP_CONFIG_DIR=/config \
  steuuu/chihuaudit:latest audit
```

📖 **Example config:** https://github.com/girste/CHIHUAUDIT/blob/main/.chihuaudit.example.yaml

## Available Tags

- `latest` - Always the newest stable version from main branch
- `main` - Alias for latest
- `main-<commit>` - Specific commit (e.g., `main-e60ce44`)
- `v0.0.1` - Release tags

**Multi-Architecture:** `linux/amd64`, `linux/arm64`

## Documentation

📚 **Full documentation:** https://github.com/girste/CHIHUAUDIT

🔐 **Security policy:** https://github.com/girste/CHIHUAUDIT/blob/main/.github/SECURITY.md

🤝 **Contributing:** https://github.com/girste/CHIHUAUDIT/blob/main/CONTRIBUTING.md

## License

MIT License - See [LICENSE](https://github.com/girste/CHIHUAUDIT/blob/main/LICENSE)

---

**⭐ Star us on GitHub:** [girste/CHIHUAUDIT](https://github.com/girste/CHIHUAUDIT)
