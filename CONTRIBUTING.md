# Contributing to Chihuaudit

Thank you for your interest in contributing! This document explains how to contribute to this project.

## How to Contribute

### Reporting Bugs

Found a bug? Please open an issue on GitHub:
- **URL:** https://github.com/girste/chihuaudit/issues/new
- Include: OS version, Go version, steps to reproduce, expected vs actual behavior

### Suggesting Enhancements

Have an idea? Open an issue with the `enhancement` label:
- **URL:** https://github.com/girste/chihuaudit/issues/new
- Describe: the problem, your proposed solution, and use cases

### Pull Requests

We use GitHub pull requests for all code contributions.

**Process:**
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes following the coding standards below
4. Run tests: `make pre-release`
5. Commit with clear messages: `git commit -m "Add feature: description"`
6. Push to your fork: `git push origin feature/your-feature-name`
7. Open a pull request against `main` branch

**Pull Request Requirements:**
- All CI checks must pass (tests, linting, security scans)
- At least 1 code review approval required
- Conversations must be resolved before merging

## Coding Standards

### Go Code

- **Go Version:** 1.23+
- **Formatting:** Use `gofmt` (run `make fmt`)
- **Linting:** Pass `go vet` and `golangci-lint` (run `make lint`)
- **Testing:** Add tests for new functionality (run `make test`)

### Code Style

```go
// Good: Clear variable names, proper error handling
func LoadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read config: %w", err)
    }
    // ...
}

// Bad: Unclear names, ignored errors
func Ld(p string) *C {
    d, _ := os.ReadFile(p)
    // ...
}
```

### Commit Messages

Follow conventional commits:
- `feat: add vulnerability intel scanner`
- `fix: correct PostgreSQL localhost detection`
- `docs: update installation instructions`
- `test: add fuzzing for config parser`

### Testing

- Write unit tests for new functions
- Use table-driven tests for multiple scenarios
- Test edge cases and error conditions
- Run `go test -v -race ./...` before committing

### Security

- Never commit secrets, API keys, or credentials
- Validate all external input
- Use prepared statements for SQL
- Follow OWASP top 10 guidelines
- Report security issues privately (see SECURITY.md)

## Development Setup

```bash
# Clone and install dependencies
git clone https://github.com/girste/chihuaudit.git
cd chihuaudit
make deps

# Build
make build

# Run tests
make test

# Run all pre-release checks
make pre-release
```

## Code Review Process

1. Maintainer reviews PR within 1-3 days
2. Feedback provided via GitHub comments
3. Author addresses feedback
4. Once approved and CI passes → merge

## Questions?

- Open a discussion: https://github.com/girste/chihuaudit/discussions
- Contact: [@girste](https://github.com/girste)

---

By contributing, you agree that your contributions will be licensed under the MIT License.
