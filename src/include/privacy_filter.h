// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * privacy_filter.h - Privacy filtering interface
 * Handles path redaction and data sanitization
 * Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6
 */

#ifndef __PRIVACY_FILTER_H__
#define __PRIVACY_FILTER_H__

#include <stdbool.h>

/**
 * Apply path redaction for privacy protection
 * 
 * Rules:
 * - /home/username/ → /home/USER/
 * - /root/ → /home/ROOT/
 * - System paths (/etc/, /usr/, /lib/, /var/lib/) preserved
 * 
 * @param path Original path
 * @param redact_enabled Whether redaction is enabled (false if --no-redact)
 * @return Redacted path (caller must free), or NULL on failure
 */
char *privacy_filter_path(const char *path, bool redact_enabled);

/**
 * Apply command line sanitization for privacy protection
 * Currently preserves command line as-is, but provides extension point
 * for future sanitization if needed
 * 
 * @param cmdline Original command line
 * @param redact_enabled Whether redaction is enabled (false if --no-redact)
 * @return Sanitized command line (caller must free), or NULL on failure
 */
char *privacy_filter_cmdline(const char *cmdline, bool redact_enabled);

#endif /* __PRIVACY_FILTER_H__ */
