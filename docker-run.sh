#!/bin/bash
# Helper script to run chihuaudit in Docker with proper host access

set -e

IMAGE="chihuaudit:latest"
COMMAND="${1:-audit}"

# Build if image doesn't exist
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Building Docker image..."
    docker build -t "$IMAGE" .
fi

# Get script directory for volume paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Get current user UID/GID for proper permissions
DOCKER_UID="${DOCKER_UID:-$(id -u)}"
DOCKER_GID="${DOCKER_GID:-$(id -g)}"

# Create volume directories if they don't exist
mkdir -p "$SCRIPT_DIR/docker-volumes"/{config,logs,data}

# Set ownership to current user
chown -R "$DOCKER_UID:$DOCKER_GID" "$SCRIPT_DIR/docker-volumes" 2>/dev/null || true

# Run with host system access + persistent volumes
docker run --rm \
    --name chihuaudit \
    --network host \
    --pid host \
    -v /proc:/host/proc:ro \
    -v /sys:/host/sys:ro \
    -v /etc:/host/etc:ro \
    -v /var/log:/host/var/log:ro \
    -v /usr/bin:/host/usr/bin:ro \
    -v /usr/sbin:/host/usr/sbin:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -v "$SCRIPT_DIR/docker-volumes/config":/config:rw \
    -v "$SCRIPT_DIR/docker-volumes/logs":/logs:rw \
    -v "$SCRIPT_DIR/docker-volumes/data":/data:rw \
    -e MCP_CONFIG_DIR=/config \
    -e MCP_LOG_DIR=/logs \
    -e MCP_DATA_DIR=/data \
    --cap-drop ALL \
    --cap-add NET_RAW \
    --cap-add DAC_READ_SEARCH \
    --security-opt no-new-privileges:true \
    --read-only \
    --user "$DOCKER_UID:$DOCKER_GID" \
    --tmpfs /tmp:rw,noexec,nosuid,size=100m \
    "$IMAGE" \
    "$COMMAND" \
    "${@:2}"
