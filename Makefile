.PHONY: build test clean install run

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

build:
	go build $(LDFLAGS) -o bin/mcp-watchdog ./cmd/mcp-watchdog

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
