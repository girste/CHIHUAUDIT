# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Report via:
- Email: **security@girste.com**
- [Private Security Advisory](https://github.com/girste/mcp-cybersec-watchdog/security/advisories/new)

Include: description, steps to reproduce, potential impact.

**Response time:** 48 hours acknowledgment, 7 days fix for critical issues.

## Security Considerations

This tool requires **passwordless sudo** for read-only access to:
- Firewall status (`ufw`, `iptables`)
- Log files (`/var/log/auth.log`)
- System info (`ss`, `systemctl`, `docker`)

**No write access** is granted.
