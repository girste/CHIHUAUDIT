.PHONY: build build-upx test clean install run lint fmt pre-release coverage coverage-html lint-full security

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/chihuaudit ./cmd/chihuaudit

build-upx: build
	@echo "=== Compressing binary with UPX ==="
	@ls -lh bin/chihuaudit | awk '{print "Before: " $$5}'
	@command -v upx >/dev/null 2>&1 || { \
		echo "❌ UPX not installed"; \
		echo "Install: apt install upx (Debian/Ubuntu) or brew install upx (macOS)"; \
		exit 1; \
	}
	upx --best --lzma bin/chihuaudit
	@ls -lh bin/chihuaudit | awk '{print "After:  " $$5}'
	@echo "✓ Binary compressed successfully"

test:
	go test -v -race ./...

coverage:
	@echo "=== Running tests with coverage ==="
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1
	@echo ""
	@echo "→ Run 'make coverage-html' to view detailed HTML report"

coverage-html: coverage
	go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

clean:
	rm -rf bin/

install:
	go install $(LDFLAGS) ./cmd/chihuaudit

run:
	go run ./cmd/chihuaudit

deps:
	go mod download
	go mod tidy

fmt:
	@echo "=== Formatting code ==="
	gofmt -w .

lint:
	@echo "=== Running linters ==="
	@echo "→ gofmt check"
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "❌ Files need formatting (run 'make fmt')" && exit 1)
	@echo "→ go vet"
	go vet ./...
	@echo "✓ All lint checks passed"

lint-full:
	@echo "=== Running golangci-lint ==="
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "❌ golangci-lint not installed"; \
		echo "Install: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin"; \
		exit 1; \
	}
	golangci-lint run --timeout=5m ./...
	@echo "✓ golangci-lint passed"

security:
	@echo "=== Running security checks ==="
	@command -v gosec >/dev/null 2>&1 || { \
		echo "Installing gosec..."; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest; \
	}
	gosec -exclude=G204,G304 ./...
	@echo "✓ Security checks passed"

pre-release: clean fmt lint test coverage build
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "  ✓ PRE-RELEASE CHECKS PASSED"
	@echo "═══════════════════════════════════════════════════════════"
	@echo "  • Code formatted with gofmt"
	@echo "  • Static analysis (go vet) passed"
	@echo "  • All tests passed with race detector"
	@echo "  • Coverage report generated"
	@echo "  • Binary built successfully (static, $(shell ls -lh bin/chihuaudit | awk '{print $$5}'))"
	@echo ""
	@echo "Optional (recommended before release):"
	@echo "  • make lint-full   - Run full linting suite"
	@echo "  • make security    - Run security scanner"
	@echo ""
	@echo "Ready for release! Next steps:"
	@echo "  1. git add -A"
	@echo "  2. git commit -m 'Release v1.x.x'"
	@echo "  3. git tag v1.x.x"
	@echo "  4. git push origin main --tags"
	@echo "═══════════════════════════════════════════════════════════"
