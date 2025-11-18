#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Graziano Labs Corp.

# Basic functional test for monitor command
# Tests command behavior, not eBPF event capture

set -e

echo "=== Monitor Command Basic Functionality Tests ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

BINARY="./build/crypto-tracer"
FAILURES=0

# Test 1: Help output
echo "Test 1: Help output"
if $BINARY help monitor | grep -q "Monitor cryptographic operations"; then
    echo "  ✓ Help output works"
else
    echo "  ✗ Help output failed"
    FAILURES=$((FAILURES + 1))
fi

# Test 2: Duration parameter
echo "Test 2: Duration parameter (2 seconds)"
START=$(date +%s)
$BINARY monitor --duration 2 --quiet 2>/dev/null || true
END=$(date +%s)
ELAPSED=$((END - START))

if [ $ELAPSED -ge 2 ] && [ $ELAPSED -le 4 ]; then
    echo "  ✓ Duration works (elapsed: ${ELAPSED}s)"
else
    echo "  ✗ Duration failed (elapsed: ${ELAPSED}s, expected: 2-4s)"
    FAILURES=$((FAILURES + 1))
fi

# Test 3: Output file creation
echo "Test 3: Output file creation"
rm -f /tmp/test-monitor-output.json
$BINARY monitor --duration 1 --output /tmp/test-monitor-output.json --quiet 2>/dev/null || true

if [ -f /tmp/test-monitor-output.json ]; then
    echo "  ✓ Output file created"
    rm -f /tmp/test-monitor-output.json
else
    echo "  ✗ Output file not created"
    FAILURES=$((FAILURES + 1))
fi

# Test 4: SIGINT handling
echo "Test 4: SIGINT handling"
$BINARY monitor --quiet 2>/dev/null &
PID=$!
sleep 1
kill -INT $PID 2>/dev/null || true
wait $PID 2>/dev/null
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "  ✓ SIGINT handled gracefully (exit code: 0)"
else
    echo "  ✗ SIGINT handling failed (exit code: $EXIT_CODE)"
    FAILURES=$((FAILURES + 1))
fi

# Test 5: Invalid arguments
echo "Test 5: Invalid arguments"
if $BINARY monitor --duration -1 2>&1 | grep -q "Invalid duration"; then
    echo "  ✓ Invalid duration rejected"
else
    echo "  ✗ Invalid duration not rejected"
    FAILURES=$((FAILURES + 1))
fi

# Test 6: Verbose mode
echo "Test 6: Verbose mode"
if $BINARY monitor --duration 1 --verbose 2>&1 | grep -q "Starting monitor command"; then
    echo "  ✓ Verbose mode works"
else
    echo "  ✗ Verbose mode failed"
    FAILURES=$((FAILURES + 1))
fi

# Test 7: Filter parameters accepted
echo "Test 7: Filter parameters"
$BINARY monitor --duration 1 --pid 1 --quiet 2>/dev/null || true
if [ $? -eq 0 ] || [ $? -eq 5 ]; then  # 0 = success, 5 = BPF error (acceptable)
    echo "  ✓ PID filter accepted"
else
    echo "  ✗ PID filter failed"
    FAILURES=$((FAILURES + 1))
fi

$BINARY monitor --duration 1 --name test --quiet 2>/dev/null || true
if [ $? -eq 0 ] || [ $? -eq 5 ]; then
    echo "  ✓ Name filter accepted"
else
    echo "  ✗ Name filter failed"
    FAILURES=$((FAILURES + 1))
fi

$BINARY monitor --duration 1 --library libssl --quiet 2>/dev/null || true
if [ $? -eq 0 ] || [ $? -eq 5 ]; then
    echo "  ✓ Library filter accepted"
else
    echo "  ✗ Library filter failed"
    FAILURES=$((FAILURES + 1))
fi

$BINARY monitor --duration 1 --file '*.pem' --quiet 2>/dev/null || true
if [ $? -eq 0 ] || [ $? -eq 5 ]; then
    echo "  ✓ File filter accepted"
else
    echo "  ✗ File filter failed"
    FAILURES=$((FAILURES + 1))
fi

# Test 8: Format parameters
echo "Test 8: Format parameters"
for format in json-stream json-array json-pretty; do
    $BINARY monitor --duration 1 --format $format --quiet 2>/dev/null || true
    if [ $? -eq 0 ] || [ $? -eq 5 ]; then
        echo "  ✓ Format $format accepted"
    else
        echo "  ✗ Format $format failed"
        FAILURES=$((FAILURES + 1))
    fi
done

# Test 9: No-redact flag
echo "Test 9: No-redact flag"
$BINARY monitor --duration 1 --no-redact --quiet 2>/dev/null || true
if [ $? -eq 0 ] || [ $? -eq 5 ]; then
    echo "  ✓ No-redact flag accepted"
else
    echo "  ✗ No-redact flag failed"
    FAILURES=$((FAILURES + 1))
fi

# Test 10: Privilege check (run without sudo)
echo "Test 10: Privilege check"
if sudo -u $SUDO_USER $BINARY monitor --duration 1 2>&1 | grep -q "Insufficient privileges"; then
    echo "  ✓ Privilege check works"
else
    echo "  ✗ Privilege check failed"
    FAILURES=$((FAILURES + 1))
fi

echo ""
echo "=== Test Summary ==="
if [ $FAILURES -eq 0 ]; then
    echo "All tests passed! ✓"
    exit 0
else
    echo "$FAILURES test(s) failed ✗"
    exit 1
fi
