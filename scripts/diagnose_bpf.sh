#!/bin/bash
# Diagnostic script for eBPF issues

echo "=== eBPF Environment Diagnostics ==="
echo ""

echo "1. Kernel Version:"
uname -r
echo ""

echo "2. BTF Support:"
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "✓ BTF available at /sys/kernel/btf/vmlinux"
    ls -lh /sys/kernel/btf/vmlinux
else
    echo "✗ BTF not available"
fi
echo ""

echo "3. BPF Filesystem:"
mount | grep bpf || echo "BPF filesystem not mounted"
echo ""

echo "4. Available Tracepoints:"
if [ -d /sys/kernel/debug/tracing/events/syscalls ]; then
    echo "Syscall tracepoints available:"
    ls /sys/kernel/debug/tracing/events/syscalls/ | grep -E "(sys_enter_open|sys_enter_openat|sched_process)" | head -10
else
    echo "Cannot access /sys/kernel/debug/tracing (need root or debugfs mount)"
fi
echo ""

echo "5. Kernel Config (BPF-related):"
if [ -f /proc/config.gz ]; then
    zgrep -E "CONFIG_BPF|CONFIG_DEBUG_INFO_BTF" /proc/config.gz | grep -v "^#"
elif [ -f /boot/config-$(uname -r) ]; then
    grep -E "CONFIG_BPF|CONFIG_DEBUG_INFO_BTF" /boot/config-$(uname -r) | grep -v "^#"
else
    echo "Kernel config not available"
fi
echo ""

echo "6. Test Simple BPF Program Load:"
if command -v bpftool &> /dev/null; then
    echo "bpftool available"
    sudo bpftool prog list | head -5
else
    echo "bpftool not available"
fi
echo ""

echo "7. libbpf Version:"
if command -v pkg-config &> /dev/null; then
    pkg-config --modversion libbpf 2>/dev/null || echo "pkg-config can't find libbpf"
else
    echo "pkg-config not available"
fi
echo ""

echo "8. Check vmlinux.h generation:"
if [ -f build/vmlinux.h ]; then
    echo "✓ vmlinux.h exists ($(wc -l < build/vmlinux.h) lines)"
    head -20 build/vmlinux.h | grep -E "(#ifndef|#define|struct)"
else
    echo "✗ vmlinux.h not found"
fi
echo ""

echo "9. Check compiled BPF objects:"
if [ -d build ]; then
    ls -lh build/*.bpf.o 2>/dev/null || echo "No BPF objects found"
else
    echo "build/ directory not found"
fi
echo ""

echo "10. Try loading file_open_trace with verbose output:"
if [ -f build/file_open_trace.bpf.o ]; then
    echo "Attempting to load file_open_trace.bpf.o..."
    sudo bpftool prog load build/file_open_trace.bpf.o /sys/fs/bpf/test_file_open 2>&1 | head -20
    sudo rm -f /sys/fs/bpf/test_file_open 2>/dev/null
else
    echo "file_open_trace.bpf.o not found"
fi
