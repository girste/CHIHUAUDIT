# Multi-stage build for minimal image
FROM golang:1.23-alpine AS builder

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
FROM alpine:3.19

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
