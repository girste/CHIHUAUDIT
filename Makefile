.PHONY: build test clean install run lint fmt pre-release

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/mcp-watchdog ./cmd/mcp-watchdog

test:
	go test -v -race ./...

clean:
	rm -rf bin/

install:
	go install $(LDFLAGS) ./cmd/mcp-watchdog

run:
	go run ./cmd/mcp-watchdog

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

pre-release: clean fmt lint test build
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "  ✓ PRE-RELEASE CHECKS PASSED"
	@echo "═══════════════════════════════════════════════════════════"
	@echo "  • Code formatted with gofmt"
	@echo "  • Static analysis (go vet) passed"
	@echo "  • All tests passed"
	@echo "  • Binary built successfully (static, $(shell ls -lh bin/mcp-watchdog | awk '{print $$5}'))"
	@echo ""
	@echo "Ready for release! Next steps:"
	@echo "  1. git add -A"
	@echo "  2. git commit -m 'Release v1.x.x'"
	@echo "  3. git tag v1.x.x"
	@echo "  4. git push origin main --tags"
	@echo "═══════════════════════════════════════════════════════════"
