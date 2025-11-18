// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * event_processor.h - Event processing pipeline interface
 * Handles event filtering, enrichment, and classification
 */

#ifndef __EVENT_PROCESSOR_H__
#define __EVENT_PROCESSOR_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "crypto_tracer.h"

/* Forward declaration */
struct ct_event_header;

/* Filter types */
typedef enum {
    FILTER_TYPE_PID,
    FILTER_TYPE_PROCESS_NAME,
    FILTER_TYPE_LIBRARY,
    FILTER_TYPE_FILE_PATH
} filter_type_t;

/* Individual filter structure */
typedef struct filter {
    filter_type_t type;
    union {
        int pid;                    /* For PID filter */
        char *name_pattern;         /* For process name (substring match) */
        char *library_pattern;      /* For library name (substring match) */
        char *file_pattern;         /* For file path (glob pattern) */
    } value;
    struct filter *next;            /* Linked list for multiple filters */
} filter_t;

/* Filter set structure */
typedef struct filter_set {
    filter_t *filters;              /* Linked list of filters */
    size_t count;                   /* Number of filters */
} filter_set_t;

/* Event processor structure */
typedef struct event_processor {
    filter_set_t *filters;          /* Filter set */
    cli_args_t *args;               /* CLI arguments for configuration */
    bool redact_paths;              /* Enable path redaction */
} event_processor_t;

/* Event processor lifecycle functions */
event_processor_t *event_processor_create(cli_args_t *args);
void event_processor_destroy(event_processor_t *proc);

/* Filter management functions */
int event_processor_add_filter(event_processor_t *proc, filter_type_t type, const void *value);
bool event_processor_matches_filters(event_processor_t *proc, processed_event_t *event);

/* Event processing functions */
int event_processor_process_event(event_processor_t *proc, 
                                   struct ct_event_header *raw_event,
                                   processed_event_t *output);

/* Event enrichment functions */
int enrich_process_name(pid_t pid, char **process_name);
int enrich_executable_path(pid_t pid, char **exe_path);
int enrich_cmdline(pid_t pid, char **cmdline);
int enrich_event(processed_event_t *event);

/* Classification functions */
file_type_t classify_crypto_file(const char *path);
const char *file_type_to_string(file_type_t type);
char *extract_library_name(const char *library_path);

/* Filter set functions */
filter_set_t *filter_set_create(void);
int filter_set_add(filter_set_t *set, filter_type_t type, const void *value);
bool filter_set_matches(filter_set_t *set, processed_event_t *event);
void filter_set_destroy(filter_set_t *set);

/* Helper functions for pattern matching */
bool glob_match(const char *pattern, const char *string);
bool substring_match(const char *pattern, const char *string);

#endif /* __EVENT_PROCESSOR_H__ */
