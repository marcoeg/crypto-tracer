// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * process_exec_trace.bpf.c - eBPF program for tracing process execution
 * Monitors sched_process_exec tracepoint for new process execution
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

/* Helper function to read command line from task */
static __always_inline void read_cmdline(struct task_struct *task, char *cmdline, int max_len) {
    struct mm_struct *mm;
    unsigned long arg_start, arg_end;
    int len;
    
    /* Read mm_struct pointer */
    mm = BPF_CORE_READ(task, mm);
    if (!mm) {
        cmdline[0] = '\0';
        return;
    }
    
    /* Read command line boundaries */
    arg_start = BPF_CORE_READ(mm, arg_start);
    arg_end = BPF_CORE_READ(mm, arg_end);
    
    /* Calculate length and truncate if needed */
    len = arg_end - arg_start;
    if (len <= 0) {
        cmdline[0] = '\0';
        return;
    }
    
    if (len > max_len - 1) {
        len = max_len - 1;
    }
    
    /* Read command line from user space */
    if (bpf_probe_read_user(cmdline, len, (void *)arg_start) < 0) {
        cmdline[0] = '\0';
        return;
    }
    
    /* Replace null bytes with spaces for readability */
    for (int i = 0; i < len && i < max_len - 1; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    
    /* Ensure null termination */
    cmdline[len] = '\0';
}

/* Tracepoint for sched_process_exec
 * This fires when a process successfully executes a new program
 */
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(void *ctx) {
    struct ct_process_exec_event *event;
    struct task_struct *task;
    __u64 pid_tgid;
    __u32 pid, ppid;
    
    /* Get current task */
    task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }
    
    /* Get PID and PPID */
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    
    /* Read PPID from task structure */
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (parent) {
        ppid = BPF_CORE_READ(parent, tgid);
    } else {
        ppid = 0;
    }
    
    /* Reserve space in ring buffer */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    /* Fill event header */
    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.pid = pid;
    event->header.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->header.event_type = CT_EVENT_PROCESS_EXEC;
    
    /* Read process name (comm) */
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));
    
    /* Store PPID */
    event->ppid = ppid;
    
    /* Read command line with safe truncation */
    read_cmdline(task, event->cmdline, sizeof(event->cmdline));
    
    /* Submit event to ring buffer */
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}