// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * crypto-tracer - Main entry point
 * Standalone eBPF-based command-line tool for monitoring cryptographic operations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/utsname.h>
#include <errno.h>
#include "include/crypto_tracer.h"

/* Minimum supported kernel version */
#define MIN_KERNEL_MAJOR 4
#define MIN_KERNEL_MINOR 15

/* Kernel version for CAP_BPF support */
#define CAP_BPF_KERNEL_MAJOR 5
#define CAP_BPF_KERNEL_MINOR 8

/* CAP_BPF capability (not defined in older headers) */
#ifndef CAP_BPF
#define CAP_BPF 39
#endif

/**
 * Parse kernel version string into major, minor, patch components
 * Returns 0 on success, -1 on failure
 */
static int parse_kernel_version(const char *version_str, int *major, int *minor, int *patch) {
    if (!version_str || !major || !minor || !patch) {
        return -1;
    }
    
    /* Skip any leading non-digit characters */
    while (*version_str && (*version_str < '0' || *version_str > '9')) {
        version_str++;
    }
    
    if (sscanf(version_str, "%d.%d.%d", major, minor, patch) < 2) {
        return -1;
    }
    
    return 0;
}

/**
 * Check if a specific capability is present
 * Returns 1 if capability is present, 0 if not, -1 on error
 */
static int has_capability(cap_value_t cap) {
    cap_t caps;
    cap_flag_value_t value;
    int result = 0;
    
    caps = cap_get_proc();
    if (!caps) {
        return -1;
    }
    
    if (cap_get_flag(caps, cap, CAP_EFFECTIVE, &value) == 0) {
        result = (value == CAP_SET) ? 1 : 0;
    } else {
        result = -1;
    }
    
    cap_free(caps);
    return result;
}

/**
 * Validate that the process has sufficient privileges to load eBPF programs
 * Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
 * Returns EXIT_SUCCESS on success, EXIT_PRIVILEGE_ERROR on failure
 */
int validate_privileges(void) {
    int has_cap_bpf = 0;
    int has_cap_sys_admin = 0;
    int is_root = 0;
    struct utsname uts;
    int major = 0, minor = 0, patch = 0;
    
    /* Check if running as root (UID 0) */
    is_root = (geteuid() == 0);
    
    /* Get kernel version to determine which capabilities to check */
    if (uname(&uts) == 0) {
        if (parse_kernel_version(uts.release, &major, &minor, &patch) == 0) {
            /* CAP_BPF is available on kernel 5.8+ */
            if (major > CAP_BPF_KERNEL_MAJOR || 
                (major == CAP_BPF_KERNEL_MAJOR && minor >= CAP_BPF_KERNEL_MINOR)) {
                has_cap_bpf = has_capability(CAP_BPF);
            }
        }
    }
    
    /* Check CAP_SYS_ADMIN (required on older kernels, alternative on newer) */
    has_cap_sys_admin = has_capability(CAP_SYS_ADMIN);
    
    /* Requirement 7.5: Accept root as sufficient privilege */
    if (is_root) {
        return EXIT_SUCCESS;
    }
    
    /* Requirement 7.4: Detect CAP_BPF on kernel 5.8+ and fall back to CAP_SYS_ADMIN */
    if (has_cap_bpf > 0 || has_cap_sys_admin > 0) {
        return EXIT_SUCCESS;
    }
    
    /* Requirement 7.2, 7.3: Exit with code 3 and display helpful error message */
    fprintf(stderr, "Error: Insufficient privileges to run crypto-tracer\n\n");
    fprintf(stderr, "crypto-tracer requires one of the following:\n");
    fprintf(stderr, "  1. Run as root: sudo crypto-tracer [options]\n");
    
    if (major > CAP_BPF_KERNEL_MAJOR || 
        (major == CAP_BPF_KERNEL_MAJOR && minor >= CAP_BPF_KERNEL_MINOR)) {
        fprintf(stderr, "  2. Grant CAP_BPF capability: sudo setcap cap_bpf+ep /path/to/crypto-tracer\n");
        fprintf(stderr, "  3. Grant CAP_SYS_ADMIN capability: sudo setcap cap_sys_admin+ep /path/to/crypto-tracer\n");
    } else {
        fprintf(stderr, "  2. Grant CAP_SYS_ADMIN capability: sudo setcap cap_sys_admin+ep /path/to/crypto-tracer\n");
        fprintf(stderr, "     (CAP_BPF is not available on kernel %d.%d, requires 5.8+)\n", major, minor);
    }
    
    fprintf(stderr, "\nNote: CAP_BPF is the preferred capability on kernel 5.8+\n");
    
    return EXIT_PRIVILEGE_ERROR;
}

/**
 * Check kernel version and compatibility
 * Requirements: 9.1, 9.2, 9.3, 9.4, 9.5
 * Returns EXIT_SUCCESS on success, EXIT_KERNEL_ERROR on failure
 */
int check_kernel_version(void) {
    struct utsname uts;
    int major = 0, minor = 0, patch = 0;
    
    /* Get kernel version information */
    if (uname(&uts) != 0) {
        fprintf(stderr, "Error: Failed to get kernel version: %s\n", strerror(errno));
        return EXIT_KERNEL_ERROR;
    }
    
    /* Parse kernel version */
    if (parse_kernel_version(uts.release, &major, &minor, &patch) != 0) {
        fprintf(stderr, "Error: Failed to parse kernel version: %s\n", uts.release);
        return EXIT_KERNEL_ERROR;
    }
    
    /* Requirement 9.1: Check for minimum kernel version 4.15+ */
    if (major < MIN_KERNEL_MAJOR || 
        (major == MIN_KERNEL_MAJOR && minor < MIN_KERNEL_MINOR)) {
        fprintf(stderr, "Error: Kernel version %d.%d.%d is not supported\n", 
                major, minor, patch);
        fprintf(stderr, "\ncrypto-tracer requires Linux kernel 4.15 or later\n");
        fprintf(stderr, "Your kernel: %s (version %d.%d.%d)\n", 
                uts.release, major, minor, patch);
        fprintf(stderr, "\nPlease upgrade your kernel to use crypto-tracer\n");
        return EXIT_KERNEL_ERROR;
    }
    
    /* Requirement 9.2: Detect CAP_BPF support on kernel 5.8+ */
    if (major > CAP_BPF_KERNEL_MAJOR || 
        (major == CAP_BPF_KERNEL_MAJOR && minor >= CAP_BPF_KERNEL_MINOR)) {
        /* CAP_BPF is available - enhanced security mode */
        if (getenv("CRYPTO_TRACER_VERBOSE")) {
            fprintf(stderr, "Info: Kernel %d.%d.%d supports CAP_BPF (enhanced security)\n",
                    major, minor, patch);
        }
    } else {
        /* Older kernel - will use CAP_SYS_ADMIN */
        if (getenv("CRYPTO_TRACER_VERBOSE")) {
            fprintf(stderr, "Info: Kernel %d.%d.%d requires CAP_SYS_ADMIN (CAP_BPF not available)\n",
                    major, minor, patch);
        }
    }
    
    /* Check for eBPF support by looking for /sys/kernel/btf/vmlinux or /proc/config.gz */
    if (access("/sys/kernel/btf/vmlinux", F_OK) == 0) {
        if (getenv("CRYPTO_TRACER_VERBOSE")) {
            fprintf(stderr, "Info: BTF support detected (CO-RE enabled)\n");
        }
    } else {
        if (getenv("CRYPTO_TRACER_VERBOSE")) {
            fprintf(stderr, "Info: BTF not available, using fallback headers\n");
        }
    }
    
    /* Requirement 9.4: Graceful feature detection - always succeed if kernel >= 4.15 */
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    int ret;
    
    (void)argc;  /* Unused for now - will be used in task 3 */
    (void)argv;  /* Unused for now - will be used in task 3 */
    
    printf("crypto-tracer v%s\n", CRYPTO_TRACER_VERSION);
    
    /* Validate privileges */
    ret = validate_privileges();
    if (ret != EXIT_SUCCESS) {
        return ret;
    }
    
    /* Check kernel version and compatibility */
    ret = check_kernel_version();
    if (ret != EXIT_SUCCESS) {
        return ret;
    }
    
    printf("Privilege and kernel checks passed\n");
    
    return EXIT_SUCCESS;
}