// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * common.h - Common definitions for eBPF programs
 * Shared event structures and constants between kernel and user space
 */

#ifndef __COMMON_H__
#define __COMMON_H__

/* When included from user-space, we need linux/types.h */
/* When included from eBPF, vmlinux.h provides all types */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* Maximum string lengths */
#define MAX_FILENAME_LEN 256
#define MAX_COMM_LEN 16
#define MAX_CMDLINE_LEN 256
#define MAX_LIBPATH_LEN 256
#define MAX_FUNCNAME_LEN 64

/* Event types */
enum ct_event_type {
    CT_EVENT_FILE_OPEN = 1,
    CT_EVENT_LIB_LOAD = 2,
    CT_EVENT_PROCESS_EXEC = 3,
    CT_EVENT_PROCESS_EXIT = 4,
    CT_EVENT_API_CALL = 5,
};

/* Base event header - prefixed with ct_ to avoid conflicts with kernel types */
struct ct_event_header {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    char comm[MAX_COMM_LEN];
    __u32 event_type;
};

/* File open event */
struct ct_file_open_event {
    struct ct_event_header header;
    char filename[MAX_FILENAME_LEN];
    __u32 flags;
    __s32 result;
};

/* Library load event */
struct ct_lib_load_event {
    struct ct_event_header header;
    char lib_path[MAX_LIBPATH_LEN];
};

/* Process execution event */
struct ct_process_exec_event {
    struct ct_event_header header;
    __u32 ppid;
    char cmdline[MAX_CMDLINE_LEN];
};

/* Process exit event */
struct ct_process_exit_event {
    struct ct_event_header header;
    __s32 exit_code;
};

/* API call event */
struct ct_api_call_event {
    struct ct_event_header header;
    char function_name[MAX_FUNCNAME_LEN];
    char library[MAX_FUNCNAME_LEN];
};

#endif /* __COMMON_H__ */