// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * lib_load_trace.bpf.c - eBPF program for tracing library loading
 * Monitors dlopen() calls for crypto library loading
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

/* Helper function to check if a string contains a substring */
static __always_inline bool str_contains(const char *haystack, const char *needle, int haystack_len) {
    int needle_len = 0;
    
    /* Calculate needle length */
    for (int i = 0; i < 32 && needle[i] != '\0'; i++) {
        needle_len++;
    }
    
    if (needle_len == 0 || haystack_len < needle_len) {
        return false;
    }
    
    /* Search for substring */
    for (int i = 0; i <= haystack_len - needle_len; i++) {
        bool match = true;
        for (int j = 0; j < needle_len; j++) {
            if (haystack[i + j] != needle[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    
    return false;
}

/* Helper function to check if library path is a crypto library */
static __always_inline bool is_crypto_library(const char *lib_path, int len) {
    /* Check for crypto library names */
    if (str_contains(lib_path, "libssl", len)) return true;
    if (str_contains(lib_path, "libcrypto", len)) return true;
    if (str_contains(lib_path, "libgnutls", len)) return true;
    if (str_contains(lib_path, "libsodium", len)) return true;
    if (str_contains(lib_path, "libnss3", len)) return true;
    if (str_contains(lib_path, "libmbedtls", len)) return true;
    
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

/* Uprobe for dlopen() function
 * dlopen() signature: void *dlopen(const char *filename, int flags)
 * On x86_64: filename is in rdi (PT_REGS_PARM1)
 */
SEC("uprobe/dlopen")
int trace_dlopen(struct pt_regs *ctx) {
    struct ct_lib_load_event *event;
    char lib_path[MAX_LIBPATH_LEN];
    const char *filename_ptr;
    int len;
    
    /* Get the filename argument (first parameter) */
    filename_ptr = (const char *)PT_REGS_PARM1(ctx);
    if (!filename_ptr) {
        return 0;
    }
    
    /* Read library path from user space */
    len = safe_read_user_str(lib_path, filename_ptr, sizeof(lib_path));
    if (len <= 0) {
        return 0;
    }
    
    /* Filter: only process crypto libraries */
    if (!is_crypto_library(lib_path, len)) {
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
    event->header.event_type = CT_EVENT_LIB_LOAD;
    
    /* Read process name (comm) */
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));
    
    /* Copy library path */
    __builtin_memcpy(event->lib_path, lib_path, sizeof(event->lib_path));
    
    /* Submit event to ring buffer */
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}