# Multi-stage build for minimal image
FROM golang:1.23-alpine@sha256:f0a8f311e13bb949e73548e67ab36055f7cfcbcd1f7892afea94c2fc1c63238b AS builder

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
FROM alpine:3.19@sha256:7d51dd030c5a0d692b8674c0b0f182ae44a4c5f0505a1235f35493e87e0cd3c2

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
