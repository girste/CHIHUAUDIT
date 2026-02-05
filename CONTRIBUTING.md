# Contributing to Chihuaudit

Thank you for your interest in contributing! 🎉

## 🎯 Philosophy

Chihuaudit is designed to be:
- **Universal**: Works on any Linux distro
- **Simple**: Minimal, readable, maintainable code
- **Safe**: Read-only checks, no system modifications
- **Portable**: Single binary, zero dependencies

## 🛠️ Development Setup

```bash
# Clone the repo
git clone https://github.com/girfest/chihuaudit.git
cd chihuaudit

# Build
make build

# Test
make test

# Run
sudo ./bin/chihuaudit audit
```

## 📋 Code Guidelines

### Style
- Use **camelCase** for private functions
- Use **CamelCase** for exported functions
- Keep functions small and focused
- Comment only when logic is non-obvious

### Portability
- **Never** hardcode paths
- Always detect tool/file existence before using
- Use `detect.CommandExists()` and `detect.FileExists()`
- Gracefully degrade if tools missing

### Security
- **Never** concatenate user input in commands
- Use `exec.Command()` with separate args
- No shell pipes or shell=true
- Read-only operations only

### Error Handling
```go
// Bad
if err != nil {
    panic(err)
}

// Good
if err != nil {
    return defaultValue
}
```

## 🧪 Adding New Checks

1. Add struct fields to `checks/types.go`
2. Implement check function in appropriate `checks/*.go`
3. Call from `CheckXXX()` orchestrator
4. Add to text formatter in `report/text.go`
5. Test on multiple distros

Example:
```go
// checks/security.go
func checkNewFeature() string {
    if !detect.CommandExists("newtool") {
        return "not available"
    }
    
    out, err := exec.Command("newtool", "--status").Output()
    if err != nil {
        return "error"
    }
    
    return strings.TrimSpace(string(out))
}
```

## 🐛 Bug Reports

Please include:
- OS and version
- Output of `chihuaudit audit`
- Expected vs actual behavior
- Steps to reproduce

## ✨ Feature Requests

Open an issue describing:
- Use case
- Expected behavior
- Why it fits Chihuaudit's philosophy

## 📝 Pull Requests

1. Fork the repo
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

### PR Guidelines
- Keep changes focused and atomic
- Update documentation if needed
- Follow existing code style
- Test on Ubuntu/Debian/RHEL if possible

## 🧹 Code Quality

Before submitting:
```bash
# Format
gofmt -w .

# Lint (if available)
golangci-lint run

# Build
make build

# Test
make test
```

## 📜 License

By contributing, you agree your code is licensed under MIT.

---

**Questions?** Open an issue or discussion!
