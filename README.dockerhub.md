<div align="center">

![Chihuaudit](https://raw.githubusercontent.com/girste/CHIHUAUDIT/main/docs/images/chihuaudit_propic.png)

# Chihuaudit

**AI-powered Linux security auditing tool**

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/girste/CHIHUAUDIT/badge)](https://securityscorecards.dev/viewer/?uri=github.com/girste/CHIHUAUDIT)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

</div>

---

## Quick Start

```bash
docker pull steuuu/chihuaudit:latest

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

## Features

- 🔍 **Complete System Audit** - Firewall, SSH, fail2ban, kernel hardening, SSL, services
- 🤖 **AI-Powered Whitelisting** - Automatic false positive elimination  
- 📊 **Continuous Monitoring** - Anomaly detection with Discord/Slack webhooks
- 🔒 **Security First** - Read-only container, minimal capabilities
- 📦 **Zero Dependencies** - Single 16MB image
- 🏆 **Production Ready** - SLSA Level 3, OpenSSF compliant

## Configuration

```bash
docker run --rm \
  -v /path/to/.chihuaudit.yaml:/config/.chihuaudit.yaml:ro \
  -e MCP_CONFIG_DIR=/config \
  steuuu/chihuaudit:latest audit
```

📖 [Example config](https://github.com/girste/CHIHUAUDIT/blob/main/.chihuaudit.example.yaml)

## Available Tags

- `latest` - Newest stable from main
- `main-<commit>` - Specific commit
- `v0.0.1` - Release tags

Multi-arch: `linux/amd64`, `linux/arm64`

## Links

📚 [Documentation](https://github.com/girste/CHIHUAUDIT) | 🔐 [Security](https://github.com/girste/CHIHUAUDIT/blob/main/.github/SECURITY.md) | 🤝 [Contributing](https://github.com/girste/CHIHUAUDIT/blob/main/CONTRIBUTING.md)

---

**⭐ Star on GitHub:** [girste/CHIHUAUDIT](https://github.com/girste/CHIHUAUDIT)
