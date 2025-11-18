// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * file_open_trace.bpf.c - eBPF program for tracing file open operations
 * Monitors sys_enter_open and sys_enter_openat for crypto file access
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1MB */
} events SEC(".maps");

/* Helper function to check if a string ends with a given suffix */
static __always_inline bool str_ends_with(const char *str, const char *suffix, int str_len) {
    int suffix_len = 0;
    
    /* Calculate suffix length */
    for (int i = 0; i < 16 && suffix[i] != '\0'; i++) {
        suffix_len++;
    }
    
    if (str_len < suffix_len) {
        return false;
    }
    
    /* Compare from the end */
    for (int i = 0; i < suffix_len; i++) {
        if (str[str_len - suffix_len + i] != suffix[i]) {
            return false;
        }
    }
    
    return true;
}

/* Helper function to check if filename is a crypto file */
static __always_inline bool is_crypto_file(const char *filename, int len) {
    /* Check for crypto file extensions */
    if (str_ends_with(filename, ".pem", len)) return true;
    if (str_ends_with(filename, ".crt", len)) return true;
    if (str_ends_with(filename, ".cer", len)) return true;
    if (str_ends_with(filename, ".key", len)) return true;
    if (str_ends_with(filename, ".p12", len)) return true;
    if (str_ends_with(filename, ".pfx", len)) return true;
    if (str_ends_with(filename, ".jks", len)) return true;
    if (str_ends_with(filename, ".keystore", len)) return true;
    
    return false;
}

/* Helper function to safely copy string from user space */
static __always_inline int safe_read_user_str(char *dst, const char *src, int max_len) {
    int ret = bpf_probe_read_user_str(dst, max_len, src);
    if (ret < 0) {
        dst[0] = '\0';
        return 0;
    }
    return ret;
}

/* Common function to handle file open events */
static __always_inline int handle_file_open(const char *filename_ptr, __u32 flags) {
    struct ct_file_open_event *event;
    char filename[MAX_FILENAME_LEN];
    int len;
    
    /* Read filename from user space */
    len = safe_read_user_str(filename, filename_ptr, sizeof(filename));
    if (len <= 0) {
        return 0;
    }
    
    /* Filter: only process crypto files */
    if (!is_crypto_file(filename, len)) {
        return 0;
    }
    
    /* Reserve space in ring buffer */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    /* Fill event header */
    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.pid = bpf_get_current_pid_tgid() >> 32;
    event->header.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->header.event_type = CT_EVENT_FILE_OPEN;
    
    /* Read process name (comm) */
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));
    
    /* Copy filename */
    __builtin_memcpy(event->filename, filename, sizeof(event->filename));
    
    /* Store flags */
    event->flags = flags;
    event->result = 0; /* Will be filled by return probe if needed */
    
    /* Submit event to ring buffer */
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

/* Tracepoint for sys_enter_open */
SEC("tracepoint/syscalls/sys_enter_open")
int trace_open_enter(struct trace_event_raw_sys_enter *ctx) {
    /* Arguments for open():
     * args[0] = const char *filename
     * args[1] = int flags
     * args[2] = umode_t mode
     */
    const char *filename = (const char *)ctx->args[0];
    __u32 flags = (__u32)ctx->args[1];
    
    return handle_file_open(filename, flags);
}

/* Tracepoint for sys_enter_openat */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    /* Arguments for openat():
     * args[0] = int dfd
     * args[1] = const char *filename
     * args[2] = int flags
     * args[3] = umode_t mode
     */
    const char *filename = (const char *)ctx->args[1];
    __u32 flags = (__u32)ctx->args[2];
    
    return handle_file_open(filename, flags);
}