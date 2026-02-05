#!/bin/bash
# Quick test script
echo "Testing chihuaudit..."
echo ""
echo "1. Testing audit command..."
sudo ./bin/chihuaudit audit | head -30
echo ""
echo "2. Testing JSON output..."
sudo ./bin/chihuaudit audit --json | jq -r '.Hostname, .OS, .Kernel' 2>/dev/null || echo "jq not installed"
echo ""
echo "All tests completed!"
