![Chihuaudit](https://raw.githubusercontent.com/girste/CHIHUAUDIT/main/docs/images/chihuaudit_cover.png)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/girste/CHIHUAUDIT/badge)](https://securityscorecards.dev/viewer/?uri=github.com/girste/CHIHUAUDIT)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Docker Pulls](https://img.shields.io/docker/pulls/steuuu/chihuaudit)](https://hub.docker.com/r/steuuu/chihuaudit)

AI-powered Linux security auditing tool with anomaly detection and real-time alerting.

## Quick Start

```bash
docker pull steuuu/chihuaudit:latest

# Run single audit
docker run --rm -v /:/host:ro steuuu/chihuaudit:latest audit

# Start monitoring (60s interval)
docker run -d --name chihuaudit-monitor \
  -v /:/host:ro \
  -e WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK \
  steuuu/chihuaudit:latest monitor --interval 60
```

## Features

- **Complete security audit**: Firewall, kernel, services, databases, SSL/TLS
- **CIS Benchmark compliance**: Automated security baseline checks
- **AI anomaly detection**: ML-powered threat detection
- **Real-time alerts**: Discord, Slack, custom webhooks
- **MCP server**: Integrate with Claude Desktop and other AI assistants

## MCP Server Setup

**Docker Compose:**
```yaml
services:
  chihuaudit:
    image: steuuu/chihuaudit:latest
    volumes:
      - /:/host:ro
      - ./chihuaudit-data:/data
    command: server --port 8080
    ports:
      - "8080:8080"
```

**Claude Desktop config** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "chihuaudit": {
      "command": "docker",
      "args": ["run", "--rm", "-v", "/:/host:ro", "steuuu/chihuaudit:latest", "server", "--stdio"]
    }
  }
}
```

Full documentation: **[GitHub Repository](https://github.com/girste/CHIHUAUDIT)**

## Images

**Docker Hub:** `steuuu/chihuaudit:latest`  
**GitHub Registry:** `ghcr.io/girste/chihuaudit:latest`

Multi-architecture: `linux/amd64`, `linux/arm64`  
Signed with: Cosign (SLSA Level 3)

## License

**Dual Licensed:**
- **MIT License** — Free and open source
- **Commercial license** available for proprietary use

Contact: **me@girste.com**

Full license: [LICENSE](https://github.com/girste/CHIHUAUDIT/blob/main/LICENSE)

---

🔗 **GitHub:** https://github.com/girste/CHIHUAUDIT  
📧 **Contact:** me@girste.com  
🌐 **Website:** https://girste.com
