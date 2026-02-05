# Development Log

## Project Overview

Chihuaudit is a universal Linux system auditing tool written in Go. It performs comprehensive system checks without requiring configuration or dependencies.

## Architecture

### Core Components

```
chihuaudit/
├── main.go              # CLI entry point (audit, monitor, init-config)
├── checks/              # Audit categories (10 modules)
│   ├── checks.go        # Orchestrator with parallel execution
│   ├── types.go         # All data structures
│   ├── security.go      # Firewall, SSH, SSL, ports, fail2ban
│   ├── services.go      # Systemd, web/DB servers
│   ├── resources.go     # CPU, RAM, disk, processes
│   ├── storage.go       # SMART, inodes, I/O
│   ├── database.go      # PostgreSQL, MySQL, Redis
│   ├── docker.go        # Container health
│   ├── system.go        # Network, cron, updates
│   ├── logs.go          # Error analysis
│   ├── network.go       # DNS, latency, interfaces
│   └── backups.go       # Backup detection
├── config/              # Configuration loading
├── detect/              # OS/tool detection utilities
├── notify/              # Discord webhook integration
├── report/              # Output formatters (text/JSON)
└── state/               # Change tracking and persistence
```

## Design Principles

### 1. Universal Portability
- **No hardcoded paths**: Always detect tool/file locations
- **Graceful degradation**: Skip checks if tools unavailable
- **Multi-distro**: Works on Ubuntu, Debian, RHEL, CentOS, Arch, Alpine

### 2. Single Binary Philosophy
- Static compilation with `CGO_ENABLED=0`
- Zero runtime dependencies
- 5MB binary size
- Docker-based reproducible builds

### 3. Safety First
- Read-only operations
- No shell injection (`exec.Command` with args)
- No user input in commands
- Silent failures (log and continue)

### 4. Performance
- Parallel execution with goroutines
- All 10 categories run simultaneously
- ~1 second for full audit (87 checks)
- Efficient state comparison

## Implementation Details

### Check Categories (87 total checks)

1. **Security** (28+ checks)
   - Firewall detection (ufw/iptables/firewalld)
   - SSH hardening (PermitRootLogin, PasswordAuth, Protocol)
   - Port separation (external vs localhost-only)
   - Unusual port detection
   - SSL certificate expiry
   - fail2ban status
   - SUID binaries
   - World-writable files
   - Failed login attempts

2. **Services** (7 checks)
   - Systemd services status
   - Failed services
   - Web servers (nginx/apache/caddy)
   - Databases (postgres/mysql/mariadb)
   - Application servers (gunicorn/node)

3. **Resources** (6 checks)
   - CPU load (1/5/15 min)
   - Memory usage
   - Disk usage per mount
   - Top processes
   - Large log files

4. **Storage** (4 checks)
   - SMART disk health
   - Inode usage
   - I/O wait
   - Filesystem errors

5. **Database** (6 checks)
   - PostgreSQL health
   - MySQL/MariaDB health
   - Redis status
   - Connection counts

6. **Docker** (5 checks)
   - Container status
   - Image inventory
   - Volume usage
   - Resource consumption

7. **System** (8 checks)
   - Listening ports
   - Active connections
   - Cron jobs
   - Systemd timers
   - Pending updates
   - NTP sync

8. **Logs** (4 checks)
   - Syslog errors
   - SSH failed attempts
   - Service restarts

9. **Network** (6 checks)
   - DNS resolution
   - Latency tests
   - Interface status
   - Top connected IPs

10. **Backups** (3 checks)
    - Backup directory detection
    - Last backup timestamp
    - Recent backup files

### State Tracking

Change detection with smart thresholds:
- CPU/RAM: Alert if >60% (configurable)
- Disk: Alert if >80% (configurable)
- Whitelist for noisy metrics (uptime, connections)
- State persisted to `/var/lib/chihuaudit/state.json`
- Fallback to `/tmp` if no write access

### Discord Notifications

Color-coded embeds:
- 🟠 Orange (0xFFA500): Warnings
- 🔴 Red (0xFF0000): Critical issues
- 🟡 Yellow (0xFFFF00): Threshold breaches

Only sends when:
- Change detected
- Threshold exceeded
- Not in whitelist

### Detection Logic

All tools/paths detected dynamically:
```go
// Good
if detect.CommandExists("smartctl") {
    checkSMART()
}

// Bad
exec.Command("/usr/sbin/smartctl")  // Never!
```

Common detection patterns:
- `detect.CommandExists()` - Check PATH
- `detect.FileExists()` - Check file presence
- `detect.TryPaths()` - Try multiple locations
- `detect.DetectFirewall()` - Auto-detect firewall type

## Build Process

### Docker Build (Recommended)
```bash
./build.sh
# Uses golang:1.21-alpine
# Outputs to bin/chihuaudit
```

### Manual Build
```bash
CGO_ENABLED=0 go build -o bin/chihuaudit -ldflags="-s -w"
```

### Makefile Targets
- `make build` - Build binary
- `make test` - Run tests
- `make clean` - Clean build artifacts
- `make install` - Install to /usr/local/bin
- `make uninstall` - Remove from system

## Testing

Tested on:
- Ubuntu 24.04 LTS ✅
- Debian 12 ✅
- RHEL 9 ✅
- Alpine 3.19 ✅

End-to-end validation:
```bash
sudo ./bin/chihuaudit audit
sudo ./bin/chihuaudit audit --json | jq .
sudo ./bin/chihuaudit monitor --interval=30s
```

## Code Quality Standards

### Naming
- `camelCase` for private functions
- `CamelCase` for exported functions/types
- Descriptive variable names

### Error Handling
```go
// Always return defaults on error
func getSomething() string {
    out, err := exec.Command("tool").Output()
    if err != nil {
        return "not available"  // Never panic
    }
    return string(out)
}
```

### Comments
- Only where logic is non-obvious
- No redundant comments
- Document exported functions

## Future Enhancements

Potential additions (maintaining simplicity):
- [ ] Systemd journal analysis
- [ ] Kernel parameter checks
- [ ] Container runtime security
- [ ] Cloud provider detection
- [ ] Minimal HTML report option

## Version History

- **v0.1 "Teacup"** (2026-02-05) - Initial release
  - 87 system checks across 10 categories
  - Discord webhook notifications
  - State tracking and monitoring mode
  - Universal Linux compatibility

---

**Development Philosophy**: Keep it simple, keep it portable, keep it safe.
