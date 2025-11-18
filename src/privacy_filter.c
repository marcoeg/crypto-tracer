// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * privacy_filter.c - Privacy filtering implementation
 * Implements path redaction and data sanitization
 * Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "include/privacy_filter.h"

/**
 * Apply path redaction for privacy protection
 * 
 * Requirement 6.1: Redact home directories (/home/user/ → /home/USER/)
 * Requirement 6.2: Redact root directory (/root/ → /home/ROOT/)
 * Requirement 6.3: Preserve system paths (/etc/, /usr/, /lib/)
 * Requirement 6.4: --no-redact flag disables all redaction
 * 
 * @param path Original path
 * @param redact_enabled Whether redaction is enabled (false if --no-redact)
 * @return Redacted path (caller must free), or NULL on failure
 */
char *privacy_filter_path(const char *path, bool redact_enabled) {
    char *result = NULL;
    const char *next_slash = NULL;
    size_t len = 0;
    
    if (!path) {
        return NULL;
    }
    
    /* If redaction is disabled, return copy of original path */
    if (!redact_enabled) {
        return strdup(path);
    }
    
    /* Rule 1: /home/username/ → /home/USER/ */
    if (strncmp(path, "/home/", 6) == 0) {
        next_slash = strchr(path + 6, '/');
        if (next_slash) {
            /* Found username between /home/ and next / */
            len = strlen("/home/USER") + strlen(next_slash) + 1;
            result = (char *)malloc(len);
            if (!result) {
                return NULL;
            }
            snprintf(result, len, "/home/USER%s", next_slash);
            return result;
        } else {
            /* Path is just /home/username with no trailing slash */
            return strdup("/home/USER");
        }
    }
    
    /* Rule 2: /root/ → /home/ROOT/ */
    if (strncmp(path, "/root/", 6) == 0) {
        len = strlen("/home/ROOT") + strlen(path + 5) + 1;
        result = (char *)malloc(len);
        if (!result) {
            return NULL;
        }
        snprintf(result, len, "/home/ROOT%s", path + 5);
        return result;
    }
    
    /* Special case: /root without trailing slash */
    if (strcmp(path, "/root") == 0) {
        return strdup("/home/ROOT");
    }
    
    /* Rule 3: System paths - no redaction */
    if (strncmp(path, "/etc/", 5) == 0 ||
        strncmp(path, "/usr/", 5) == 0 ||
        strncmp(path, "/lib/", 5) == 0 ||
        strncmp(path, "/lib64/", 7) == 0 ||
        strncmp(path, "/var/lib/", 9) == 0 ||
        strncmp(path, "/sys/", 5) == 0 ||
        strncmp(path, "/proc/", 6) == 0 ||
        strncmp(path, "/dev/", 5) == 0 ||
        strncmp(path, "/tmp/", 5) == 0 ||
        strncmp(path, "/opt/", 5) == 0 ||
        strncmp(path, "/bin/", 5) == 0 ||
        strncmp(path, "/sbin/", 6) == 0) {
        return strdup(path);
    }
    
    /* Default: return copy of original path */
    return strdup(path);
}

/**
 * Apply command line sanitization for privacy protection
 * 
 * Currently preserves command line as-is per design document.
 * Provides extension point for future sanitization if needed.
 * 
 * Requirement 6.5: Never log private key content, passwords, or plaintext data
 * Requirement 6.6: Only include metadata (filenames, function names, timestamps)
 * 
 * @param cmdline Original command line
 * @param redact_enabled Whether redaction is enabled (false if --no-redact)
 * @return Sanitized command line (caller must free), or NULL on failure
 */
char *privacy_filter_cmdline(const char *cmdline, bool redact_enabled) {
    if (!cmdline) {
        return NULL;
    }
    
    /* If redaction is disabled, return copy of original */
    if (!redact_enabled) {
        return strdup(cmdline);
    }
    
    /* Currently no command line sanitization beyond path redaction
     * which is handled separately. This function provides an extension
     * point for future enhancements if needed.
     */
    return strdup(cmdline);
}
