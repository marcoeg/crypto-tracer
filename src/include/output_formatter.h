// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * output_formatter.h - JSON output formatting interface
 * Handles JSON formatting for events, profiles, and snapshots
 * Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
 */

#ifndef __OUTPUT_FORMATTER_H__
#define __OUTPUT_FORMATTER_H__

#include <stdio.h>
#include <stdbool.h>
#include "crypto_tracer.h"

/* Output formatter structure */
typedef struct output_formatter {
    output_format_t format;         /* Output format type */
    FILE *output;                   /* Output file handle */
    bool first_event;               /* Track first event for JSON array */
    bool array_started;             /* Track if JSON array has been started */
} output_formatter_t;

/* Lifecycle functions */
output_formatter_t *output_formatter_create(output_format_t format, FILE *output);
void output_formatter_destroy(output_formatter_t *fmt);

/* Event formatting functions */
int output_formatter_write_event(output_formatter_t *fmt, processed_event_t *event);
int output_formatter_write_profile(output_formatter_t *fmt, profile_t *profile);
int output_formatter_write_snapshot(output_formatter_t *fmt, snapshot_t *snapshot);
int output_formatter_finalize(output_formatter_t *fmt);

/* Timestamp formatting */
char *format_timestamp_iso8601(uint64_t timestamp_ns);

/* JSON escaping */
char *json_escape_string(const char *str);

#endif /* __OUTPUT_FORMATTER_H__ */
