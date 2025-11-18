// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * process_exit_trace.bpf.c - eBPF program for tracing process exit
 * Monitors sched_process_exit tracepoint for process termination
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

/* Hash map to track process start times (for cleanup) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);    /* PID */
    __type(value, __u64);  /* timestamp */
} process_start_time SEC(".maps");

/* Tracepoint for sched_process_exit
 * This fires when a process exits
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(void *ctx) {
    struct ct_process_exit_event *event;
    struct task_struct *task;
    __u64 pid_tgid;
    __u32 pid;
    __s32 exit_code;
    
    /* Get current task */
    task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }
    
    /* Get PID */
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    
    /* Read exit code from task structure */
    exit_code = BPF_CORE_READ(task, exit_code);
    
    /* Reserve space in ring buffer */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        /* Still clean up the map entry even if we can't send event */
        bpf_map_delete_elem(&process_start_time, &pid);
        return 0;
    }
    
    /* Fill event header */
    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.pid = pid;
    event->header.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->header.event_type = CT_EVENT_PROCESS_EXIT;
    
    /* Read process name (comm) */
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));
    
    /* Store exit code */
    event->exit_code = exit_code;
    
    /* Submit event to ring buffer */
    bpf_ringbuf_submit(event, 0);
    
    /* Clean up process tracking map */
    bpf_map_delete_elem(&process_start_time, &pid);
    
    return 0;
}