#!/bin/bash
set -e

TARGET="${1:-agent}"

case "$TARGET" in
  cloud)
    echo "Building chihuaudit-cloud with Docker..."
    docker run --rm \
      -v "$PWD":/app \
      -w /app \
      golang:alpine \
      sh -c "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o bin/chihuaudit-cloud ./cmd/chihuaudit-cloud"
    echo "Build complete: bin/chihuaudit-cloud"
    ls -lh bin/chihuaudit-cloud
    ;;
  *)
    echo "Building chihuaudit with Docker..."
    docker run --rm \
      -v "$PWD":/app \
      -w /app \
      golang:alpine \
      sh -c "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o bin/chihuaudit"
    echo "Build complete: bin/chihuaudit"
    ls -lh bin/chihuaudit
    ;;
esac
