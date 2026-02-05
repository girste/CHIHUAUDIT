# Installation Guide

## 🚀 Quick Install

### Option 1: Build from Source

```bash
git clone https://github.com/girfest/chihuaudit.git
cd chihuaudit
make build
sudo cp bin/chihuaudit /usr/local/bin/
```

### Option 2: Docker Build

```bash
git clone https://github.com/girfest/chihuaudit.git
cd chihuaudit
./build.sh  # Uses Docker for reproducible builds
sudo cp bin/chihuaudit /usr/local/bin/
```

## 📦 Requirements

### Runtime
- Linux kernel 2.6+
- **No dependencies** - static binary

### Build
- Docker (for build.sh)
- OR Go 1.21+ (for manual build)

## 🔧 Configuration (Optional)

```bash
# Generate default config
chihuaudit init-config

# Edit config
nano ~/.chihuaudit/config.json
```

Add Discord webhook for monitoring:
```json
{
  "discord_webhook": "https://discord.com/api/webhooks/YOUR_WEBHOOK",
  "notification_whitelist": {
    "cpu_threshold": 70,
    "memory_threshold": 70,
    "disk_threshold": 85,
    "ignore_changes": ["uptime", "active_connections"]
  }
}
```

## 🎯 Usage

### Single Audit
```bash
sudo chihuaudit audit
```

### JSON Output
```bash
sudo chihuaudit audit --json | jq .
```

### Continuous Monitoring
```bash
# Default 5 minute interval
sudo chihuaudit monitor

# Custom interval
sudo chihuaudit monitor --interval=10m
```

## 🐧 Tested Distributions

- ✅ Ubuntu 20.04, 22.04, 24.04
- ✅ Debian 11, 12
- ✅ RHEL 8, 9
- ✅ CentOS 7, 8
- ✅ Fedora 38+
- ✅ Arch Linux
- ✅ Alpine Linux

Should work on any systemd-based Linux.

## 🔐 Permissions

Most checks work without sudo, but some require elevated privileges:
- Firewall rules
- System logs
- All network connections
- Failed login attempts

## 🚫 Uninstall

```bash
sudo rm /usr/local/bin/chihuaudit
rm -rf ~/.chihuaudit
```

## 🆘 Troubleshooting

### "command not found"
Ensure `/usr/local/bin` is in your `$PATH`:
```bash
echo $PATH
export PATH=$PATH:/usr/local/bin
```

### Build fails
Use Docker build for reproducible results:
```bash
./build.sh
```

### Permission denied
Run with sudo for full audit:
```bash
sudo chihuaudit audit
```

---

**Need help?** Open an issue on GitHub!
