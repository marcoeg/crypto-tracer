// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * openssl_api_trace.bpf.c - eBPF program for tracing OpenSSL API calls (optional)
 * Monitors OpenSSL API functions for SSL/TLS operations
 * NOTE: This is an optional P1 feature, not required for v1.0 MVP
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

/* Helper function to copy string literal */
static __always_inline void copy_string(char *dst, const char *src, int max_len) {
    int i;
    for (i = 0; i < max_len - 1 && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

/* Common function to handle API call events */
static __always_inline int handle_api_call(const char *function_name) {
    struct ct_api_call_event *event;
    
    /* Reserve space in ring buffer */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    /* Fill event header */
    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.pid = bpf_get_current_pid_tgid() >> 32;
    event->header.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->header.event_type = CT_EVENT_API_CALL;
    
    /* Read process name (comm) */
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));
    
    /* Copy function name */
    copy_string(event->function_name, function_name, sizeof(event->function_name));
    
    /* Set library name */
    copy_string(event->library, "libssl", sizeof(event->library));
    
    /* Submit event to ring buffer */
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

/* Uprobe for SSL_CTX_new() function
 * SSL_CTX *SSL_CTX_new(const SSL_METHOD *method)
 * This creates a new SSL context
 */
SEC("uprobe/SSL_CTX_new")
int trace_ssl_ctx_new(struct pt_regs *ctx) {
    return handle_api_call("SSL_CTX_new");
}

/* Uprobe for SSL_connect() function
 * int SSL_connect(SSL *ssl)
 * This initiates an SSL/TLS handshake with a server
 */
SEC("uprobe/SSL_connect")
int trace_ssl_connect(struct pt_regs *ctx) {
    return handle_api_call("SSL_connect");
}

/* Uprobe for SSL_accept() function
 * int SSL_accept(SSL *ssl)
 * This waits for an SSL/TLS client to initiate a handshake
 */
SEC("uprobe/SSL_accept")
int trace_ssl_accept(struct pt_regs *ctx) {
    return handle_api_call("SSL_accept");
}