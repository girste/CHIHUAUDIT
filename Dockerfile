# Multi-stage build for minimal image
FROM golang:1.23-alpine@sha256:383395b794dffa5b53012a212365d40c8e37109a626ca30d6151c8348d380b5f AS builder

# Install build dependencies
RUN apk add --no-cache git make

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build static binary with multi-arch support
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty)" \
    -o chihuaudit \
    ./cmd/chihuaudit

# Final stage - minimal alpine
FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy binary from builder
COPY --from=builder /build/chihuaudit /usr/local/bin/chihuaudit

# Health check - verify binary is executable and responds
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/local/bin/chihuaudit version || exit 1

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/chihuaudit"]

# Default command
CMD ["audit", "--format=json"]
