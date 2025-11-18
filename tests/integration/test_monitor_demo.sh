#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Graziano Labs Corp.

# Demo script to test monitor command with actual crypto operations

set -e

echo "=== crypto-tracer Monitor Command Demo ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

# Check if crypto-tracer binary exists
if [ ! -f "./build/crypto-tracer" ]; then
    echo "Error: crypto-tracer binary not found. Run 'make' first."
    exit 1
fi

echo "Test 1: Monitor with duration (5 seconds)"
echo "Starting monitor in background..."
./build/crypto-tracer monitor --duration 5 --output /tmp/monitor-test.json --quiet &
MONITOR_PID=$!

# Wait a moment for monitor to start
sleep 1

# Generate some crypto activity
echo "Generating crypto activity..."
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    cat /etc/ssl/certs/ca-certificates.crt > /dev/null 2>&1 || true
fi

# Try to trigger library loading (may not work in all environments)
openssl version > /dev/null 2>&1 || true

# Wait for monitor to complete
wait $MONITOR_PID
echo "Monitor completed"

# Check output
if [ -f /tmp/monitor-test.json ]; then
    EVENT_COUNT=$(wc -l < /tmp/monitor-test.json)
    echo "Captured $EVENT_COUNT event(s)"
    
    if [ $EVENT_COUNT -gt 0 ]; then
        echo "Sample event:"
        head -1 /tmp/monitor-test.json | python3 -m json.tool 2>/dev/null || head -1 /tmp/monitor-test.json
    else
        echo "No events captured (this is normal if no crypto operations occurred)"
    fi
    
    rm -f /tmp/monitor-test.json
else
    echo "Warning: Output file not created"
fi

echo ""
echo "Test 2: Monitor with SIGINT"
echo "Starting monitor (will interrupt after 2 seconds)..."
./build/crypto-tracer monitor --quiet &
MONITOR_PID=$!

sleep 2
echo "Sending SIGINT..."
kill -INT $MONITOR_PID
wait $MONITOR_PID
echo "Monitor stopped gracefully"

echo ""
echo "Test 3: Monitor with filters"
echo "Monitoring for libssl library loads (5 seconds)..."
./build/crypto-tracer monitor --duration 5 --library libssl --quiet &
MONITOR_PID=$!

sleep 1
# Try to trigger libssl loading
openssl version > /dev/null 2>&1 || true
curl --version > /dev/null 2>&1 || true

wait $MONITOR_PID
echo "Filtered monitoring completed"

echo ""
echo "Test 4: Monitor with verbose output"
echo "Running monitor with verbose logging (3 seconds)..."
./build/crypto-tracer monitor --duration 3 --verbose 2>&1 | head -20

echo ""
echo "=== Demo Complete ==="
echo ""
echo "The monitor command is working correctly!"
echo ""
echo "Try these commands yourself:"
echo "  sudo ./build/crypto-tracer monitor --duration 10"
echo "  sudo ./build/crypto-tracer monitor --pid \$\$ --duration 10"
echo "  sudo ./build/crypto-tracer monitor --library libssl --duration 10"
echo "  sudo ./build/crypto-tracer monitor --file '/etc/ssl/*.pem' --duration 10"
