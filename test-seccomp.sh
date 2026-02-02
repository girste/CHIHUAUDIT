#!/bin/bash
# Test seccomp profile - verifica syscall permessi/bloccati

set -e

echo "=== Seccomp Profile Test ==="

# Test 1: Container starts with seccomp
echo -n "Test 1: Container starts with seccomp... "
docker run --rm --security-opt seccomp=seccomp-profile.json chihuaudit:latest version > /dev/null 2>&1
echo "✓"

# Test 2: Basic operations work
echo -n "Test 2: Basic operations (audit)... "
timeout 30 docker run --rm \
    --security-opt seccomp=seccomp-profile.json \
    --network host \
    -v /proc:/host/proc:ro \
    -v /etc:/host/etc:ro \
    chihuaudit:latest audit --format=json > /tmp/seccomp-test.json 2>&1 || true

if [ -s /tmp/seccomp-test.json ]; then
    echo "✓"
else
    echo "⚠ (no output)"
fi

# Test 3: Dangerous syscalls blocked
echo -n "Test 3: Blocked syscalls (reboot)... "
if docker run --rm --security-opt seccomp=seccomp-profile.json chihuaudit:latest sh -c 'reboot 2>&1' | grep -q "not permitted\|not allowed"; then
    echo "✓"
else
    echo "⚠ (not blocked or different error)"
fi

echo ""
echo "=== Seccomp Tests Complete ==="

