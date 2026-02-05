#!/bin/bash
set -e

echo "Building chihuaudit with Docker..."

docker run --rm \
  -v "$PWD":/app \
  -w /app \
  golang:1.21-alpine \
  sh -c "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o bin/chihuaudit"

echo "Build complete: bin/chihuaudit"
ls -lh bin/chihuaudit
