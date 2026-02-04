# CHIHUAUDIT v0.0.7-teacup Release Notes

**Release Date:** 2026-02-04  
**Type:** Major Refactoring - Docker-First Architecture

## 🎯 Summary

CHIHUAUDIT v0.0.7-teacup represents a complete architectural refactoring focused on Docker-first deployment, code quality, and operational simplicity. This release eliminates bloat, removes redundancies, and provides a clean, maintainable codebase.

## 🚀 What's New

### Docker-First Architecture
- **Standalone distributed model**: Each server runs its own container
- **No central manager needed**: Eliminates single point of failure
- **Webhook-based centralization**: Discord/Slack for unified alerting
- **Infinite scalability**: Just add more containers
- **16MB image, ~1MB RAM, 0% CPU** when idle

### Code Quality Improvements
- **96% reduction in main.go**: From 1,430 lines to 57 lines
- **Modular command structure**: 7 separate command files
- **Zero code duplication**: Shared utilities properly extracted
- **Consistent naming**: Go best practices throughout
- **Clean imports**: Proper package organization

### Simplified Commands
**Removed redundant commands:**
- ~~`test`~~ → Use `audit` instead
- ~~`daemon`~~ → Use Docker restart policies
- ~~`monitor-once`~~ → Use `monitor --once`
- ~~`monitor-status`~~ → Use Docker `ps`/`logs`

**Final command set:**
```
audit       - Run security audit
monitor     - Continuous monitoring (with --once flag)
baseline    - Manage configuration baselines
whitelist   - Manage alert code whitelist
serve       - Start MCP server
verify      - Verify prerequisites
version     - Show version
help        - Show help
```

## 📦 Installation

### Docker (Recommended)
```bash
# Pull image
docker pull girste/chihuaudit:0.0.7-teacup

# One-time audit
docker run --rm \
  --network=host --pid=host \
  -v /:/host:ro \
  girste/chihuaudit:0.0.7-teacup audit

# Continuous monitoring
docker run -d \
  --name=chihuaudit-monitor \
  --restart=unless-stopped \
  --network=host --pid=host \
  -v /:/host:ro \
  -v ./config:/config \
  girste/chihuaudit:0.0.7-teacup monitor --interval 300
```

### Docker Compose
```bash
git clone https://github.com/girste/CHIHUAUDIT.git
cd CHIHUAUDIT
docker-compose up -d chihuaudit-monitor
```

## 🔧 Technical Changes

### Code Organization
**New package structure:**
```
cmd/chihuaudit/
├── main.go (57 lines - just routing)
└── commands/
    ├── audit.go (193 lines)
    ├── baseline.go (325 lines)
    ├── help.go (90 lines)
    ├── monitor.go (65 lines)
    ├── serve.go (156 lines)
    ├── verify.go (40 lines)
    └── whitelist.go (197 lines)

internal/
├── util/
│   ├── version.go (Version constant)
│   └── dirs.go (GetLogDir, GetConfigDir)
├── config/
│   └── whitelist.go (LoadOrCreateWhitelist, GetWhitelistPath, SaveWhitelist)
└── output/
    └── formatter.go (FormatDriftText)
```

### Eliminated Duplications
- Removed duplicate `getLogDir()` from `mcp/server.go`
- Centralized whitelist operations in `config` package
- Moved drift formatting to `output` package
- Merged `serve`/`server` modes into single implementation

### Improved Help System
- Simplified help text (Docker-focused)
- Clear command descriptions
- Removed mention of deprecated commands
- Added distributed architecture diagram

## 🧪 Testing

**All checks passed:**
- ✅ Linters (`make lint`)
- ✅ Unit tests (`make test`)
- ✅ Docker build
- ✅ Command functionality
- ✅ MCP server
- ✅ Webhook notifications

## 📊 Comparison

| Metric | v0.0.6-teacup | v0.0.7-teacup | Change |
|--------|---------------|---------------|--------|
| main.go lines | 1,430 | 57 | **-96%** |
| Commands | 11 | 8 | -27% |
| Code duplications | Multiple | 0 | **-100%** |
| Package organization | Monolithic | Modular | **✅** |
| Docker-first docs | No | Yes | **✅** |
| Naming consistency | Mixed | Consistent | **✅** |

## 🔐 Security

**No security changes** - all existing security features maintained:
- ✅ Signed baselines
- ✅ Alert codes
- ✅ Drift detection
- ✅ Webhook notifications
- ✅ Whitelist system
- ✅ SLSA Level 3
- ✅ OpenSSF Best Practices badge added

## 🐛 Breaking Changes

**Removed Commands:**
If you were using these, here's the migration:
- `chihuaudit test` → `chihuaudit audit --format=json`
- `chihuaudit daemon start` → `docker run -d chihuaudit monitor`
- `chihuaudit monitor-once` → `chihuaudit monitor --once`
- `chihuaudit monitor-status` → `docker ps | grep chihuaudit`

**Binary Installation:**
Binary releases are no longer the recommended installation method. Use Docker instead for production deployments.

## 📚 Documentation Updates

- ✅ README.md updated with Docker-first approach
- ✅ OpenSSF Best Practices badge added
- ✅ Distributed architecture diagram
- ✅ Version updated to 0.0.7-teacup
- ✅ Installation section rewritten
- ✅ Command list simplified

## 🙏 Acknowledgments

This release focused on addressing technical debt and improving developer experience while maintaining 100% feature parity.

## 🔗 Links

- **Repository:** https://github.com/girste/CHIHUAUDIT
- **Docker Hub:** https://hub.docker.com/r/girste/chihuaudit
- **GitHub Container Registry:** ghcr.io/girste/chihuaudit
- **Issues:** https://github.com/girste/CHIHUAUDIT/issues
- **Security:** See SECURITY.md

## 📝 Full Changelog

See https://github.com/girste/CHIHUAUDIT/compare/v0.0.6-teacup...v0.0.7-teacup

---

**Docker-first. Distributed. Simple.**
