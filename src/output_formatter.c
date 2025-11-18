// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * output_formatter.c - JSON output formatting implementation
 * Implements JSON formatting for all event types
 * Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "include/output_formatter.h"
#include "include/event_processor.h"

/**
 * Create a new output formatter
 * 
 * @param format Output format type
 * @param output Output file handle (must be open)
 * @return Pointer to formatter, or NULL on failure
 */
output_formatter_t *output_formatter_create(output_format_t format, FILE *output) {
    output_formatter_t *fmt = NULL;
    
    if (!output) {
        return NULL;
    }
    
    fmt = (output_formatter_t *)calloc(1, sizeof(output_formatter_t));
    if (!fmt) {
        fprintf(stderr, "Error: Failed to allocate output formatter\n");
        return NULL;
    }
    
    fmt->format = format;
    fmt->output = output;
    fmt->first_event = true;
    fmt->array_started = false;
    
    /* For JSON array format, start the array */
    if (format == FORMAT_JSON_ARRAY) {
        fprintf(output, "[\n");
        fmt->array_started = true;
    }
    
    return fmt;
}

/**
 * Finalize output (close JSON array if needed)
 * 
 * @param fmt Output formatter
 * @return 0 on success, -1 on failure
 */
int output_formatter_finalize(output_formatter_t *fmt) {
    if (!fmt || !fmt->output) {
        return -1;
    }
    
    /* Close JSON array if it was started */
    if (fmt->format == FORMAT_JSON_ARRAY && fmt->array_started) {
        fprintf(fmt->output, "\n]\n");
        fflush(fmt->output);
    }
    
    return 0;
}

/**
 * Destroy output formatter
 * Note: Does not close the output file handle (caller's responsibility)
 * 
 * @param fmt Output formatter to destroy
 */
void output_formatter_destroy(output_formatter_t *fmt) {
    if (!fmt) {
        return;
    }
    
    /* Finalize output before destroying */
    output_formatter_finalize(fmt);
    
    free(fmt);
}

/**
 * Format timestamp as ISO 8601 with microsecond precision
 * Requirement: 10.4 - ISO 8601 format with microsecond precision
 * 
 * Format: YYYY-MM-DDTHH:MM:SS.ssssssZ
 * 
 * @param timestamp_ns Timestamp in nanoseconds
 * @return Formatted timestamp string (caller must free), or NULL on failure
 */
char *format_timestamp_iso8601(uint64_t timestamp_ns) {
    struct tm tm_info;
    time_t seconds;
    uint64_t microseconds;
    char buffer[64];
    char *result = NULL;
    
    /* Convert nanoseconds to seconds and microseconds */
    seconds = timestamp_ns / 1000000000ULL;
    microseconds = (timestamp_ns % 1000000000ULL) / 1000ULL;
    
    /* Convert to UTC time */
    if (gmtime_r(&seconds, &tm_info) == NULL) {
        return NULL;
    }
    
    /* Format: YYYY-MM-DDTHH:MM:SS.ssssssZ */
    snprintf(buffer, sizeof(buffer), 
             "%04d-%02d-%02dT%02d:%02d:%02d.%06luZ",
             tm_info.tm_year + 1900,
             tm_info.tm_mon + 1,
             tm_info.tm_mday,
             tm_info.tm_hour,
             tm_info.tm_min,
             tm_info.tm_sec,
             (unsigned long)microseconds);
    
    result = strdup(buffer);
    return result;
}

/**
 * Escape string for JSON output
 * Handles: ", \, /, \b, \f, \n, \r, \t, and control characters
 * 
 * @param str String to escape
 * @return Escaped string (caller must free), or NULL on failure
 */
char *json_escape_string(const char *str) {
    size_t len, i, j;
    char *escaped = NULL;
    
    if (!str) {
        return strdup("");
    }
    
    len = strlen(str);
    
    /* Worst case: every character needs escaping (2x size) + null terminator */
    escaped = (char *)malloc(len * 2 + 1);
    if (!escaped) {
        return NULL;
    }
    
    j = 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        
        switch (c) {
            case '"':
                escaped[j++] = '\\';
                escaped[j++] = '"';
                break;
            case '\\':
                escaped[j++] = '\\';
                escaped[j++] = '\\';
                break;
            case '/':
                escaped[j++] = '\\';
                escaped[j++] = '/';
                break;
            case '\b':
                escaped[j++] = '\\';
                escaped[j++] = 'b';
                break;
            case '\f':
                escaped[j++] = '\\';
                escaped[j++] = 'f';
                break;
            case '\n':
                escaped[j++] = '\\';
                escaped[j++] = 'n';
                break;
            case '\r':
                escaped[j++] = '\\';
                escaped[j++] = 'r';
                break;
            case '\t':
                escaped[j++] = '\\';
                escaped[j++] = 't';
                break;
            default:
                /* Control characters (0x00-0x1F) need \uXXXX encoding */
                if (c < 0x20) {
                    j += snprintf(&escaped[j], 7, "\\u%04x", c);
                } else {
                    escaped[j++] = c;
                }
                break;
        }
    }
    
    escaped[j] = '\0';
    return escaped;
}

/**
 * Write a JSON field (key-value pair)
 * Helper function to reduce code duplication
 */
static void write_json_field_string(FILE *output, const char *key, const char *value, 
                                     bool is_last, int indent) {
    char *escaped = NULL;
    int i;
    
    if (!output || !key) {
        return;
    }
    
    /* Indent */
    for (i = 0; i < indent; i++) {
        fprintf(output, "  ");
    }
    
    if (value) {
        escaped = json_escape_string(value);
        fprintf(output, "\"%s\": \"%s\"", key, escaped ? escaped : "");
        free(escaped);
    } else {
        fprintf(output, "\"%s\": null", key);
    }
    
    if (!is_last) {
        fprintf(output, ",");
    }
    fprintf(output, "\n");
}

static void write_json_field_int(FILE *output, const char *key, int value, 
                                  bool is_last, int indent) {
    int i;
    
    if (!output || !key) {
        return;
    }
    
    /* Indent */
    for (i = 0; i < indent; i++) {
        fprintf(output, "  ");
    }
    
    fprintf(output, "\"%s\": %d", key, value);
    
    if (!is_last) {
        fprintf(output, ",");
    }
    fprintf(output, "\n");
}

static void write_json_field_uint(FILE *output, const char *key, unsigned int value, 
                                   bool is_last, int indent) {
    int i;
    
    if (!output || !key) {
        return;
    }
    
    /* Indent */
    for (i = 0; i < indent; i++) {
        fprintf(output, "  ");
    }
    
    fprintf(output, "\"%s\": %u", key, value);
    
    if (!is_last) {
        fprintf(output, ",");
    }
    fprintf(output, "\n");
}

/**
 * Write a file_open event as JSON
 * Requirement: 10.1 - Valid JSON for all event types
 */
static int write_file_open_event_json(FILE *output, processed_event_t *event, bool compact) {
    char *escaped = NULL;
    
    if (!output || !event) {
        return -1;
    }
    
    if (compact) {
        /* Compact format for json-stream */
        fprintf(output, "\"event_type\":\"file_open\",");
        
        if (event->timestamp) {
            escaped = json_escape_string(event->timestamp);
            fprintf(output, "\"timestamp\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        }
        
        fprintf(output, "\"pid\":%u,\"uid\":%u,", event->pid, event->uid);
        
        if (event->process) {
            escaped = json_escape_string(event->process);
            fprintf(output, "\"process\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"process\":null,");
        }
        
        if (event->exe) {
            escaped = json_escape_string(event->exe);
            fprintf(output, "\"exe\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"exe\":null,");
        }
        
        if (event->file) {
            escaped = json_escape_string(event->file);
            fprintf(output, "\"file\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"file\":null,");
        }
        
        fprintf(output, "\"file_type\":\"%s\",", file_type_to_string(event->file_type));
        
        if (event->flags) {
            escaped = json_escape_string(event->flags);
            fprintf(output, "\"flags\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"flags\":null,");
        }
        
        fprintf(output, "\"result\":%d", event->result);
    } else {
        /* Pretty format */
        write_json_field_string(output, "event_type", event->event_type, false, 1);
        write_json_field_string(output, "timestamp", event->timestamp, false, 1);
        write_json_field_uint(output, "pid", event->pid, false, 1);
        write_json_field_uint(output, "uid", event->uid, false, 1);
        write_json_field_string(output, "process", event->process, false, 1);
        write_json_field_string(output, "exe", event->exe, false, 1);
        write_json_field_string(output, "file", event->file, false, 1);
        write_json_field_string(output, "file_type", file_type_to_string(event->file_type), false, 1);
        write_json_field_string(output, "flags", event->flags, false, 1);
        write_json_field_int(output, "result", event->result, true, 1);
    }
    
    return 0;
}

/**
 * Write a lib_load event as JSON
 * Requirement: 10.1 - Valid JSON for all event types
 */
static int write_lib_load_event_json(FILE *output, processed_event_t *event, bool compact) {
    char *escaped = NULL;
    
    if (!output || !event) {
        return -1;
    }
    
    if (compact) {
        /* Compact format for json-stream */
        fprintf(output, "\"event_type\":\"lib_load\",");
        
        if (event->timestamp) {
            escaped = json_escape_string(event->timestamp);
            fprintf(output, "\"timestamp\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        }
        
        fprintf(output, "\"pid\":%u,\"uid\":%u,", event->pid, event->uid);
        
        if (event->process) {
            escaped = json_escape_string(event->process);
            fprintf(output, "\"process\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"process\":null,");
        }
        
        if (event->exe) {
            escaped = json_escape_string(event->exe);
            fprintf(output, "\"exe\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"exe\":null,");
        }
        
        if (event->library) {
            escaped = json_escape_string(event->library);
            fprintf(output, "\"library\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"library\":null,");
        }
        
        if (event->library_name) {
            escaped = json_escape_string(event->library_name);
            fprintf(output, "\"library_name\":\"%s\"", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"library_name\":null");
        }
    } else {
        /* Pretty format */
        write_json_field_string(output, "event_type", event->event_type, false, 1);
        write_json_field_string(output, "timestamp", event->timestamp, false, 1);
        write_json_field_uint(output, "pid", event->pid, false, 1);
        write_json_field_uint(output, "uid", event->uid, false, 1);
        write_json_field_string(output, "process", event->process, false, 1);
        write_json_field_string(output, "exe", event->exe, false, 1);
        write_json_field_string(output, "library", event->library, false, 1);
        write_json_field_string(output, "library_name", event->library_name, true, 1);
    }
    
    return 0;
}

/**
 * Write a process_exec event as JSON
 * Requirement: 10.1 - Valid JSON for all event types
 */
static int write_process_exec_event_json(FILE *output, processed_event_t *event, bool compact) {
    char *escaped = NULL;
    
    if (!output || !event) {
        return -1;
    }
    
    if (compact) {
        /* Compact format for json-stream */
        fprintf(output, "\"event_type\":\"process_exec\",");
        
        if (event->timestamp) {
            escaped = json_escape_string(event->timestamp);
            fprintf(output, "\"timestamp\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        }
        
        fprintf(output, "\"pid\":%u,\"uid\":%u,", event->pid, event->uid);
        
        if (event->process) {
            escaped = json_escape_string(event->process);
            fprintf(output, "\"process\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"process\":null,");
        }
        
        if (event->exe) {
            escaped = json_escape_string(event->exe);
            fprintf(output, "\"exe\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"exe\":null,");
        }
        
        if (event->cmdline) {
            escaped = json_escape_string(event->cmdline);
            fprintf(output, "\"cmdline\":\"%s\"", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"cmdline\":null");
        }
    } else {
        /* Pretty format */
        write_json_field_string(output, "event_type", event->event_type, false, 1);
        write_json_field_string(output, "timestamp", event->timestamp, false, 1);
        write_json_field_uint(output, "pid", event->pid, false, 1);
        write_json_field_uint(output, "uid", event->uid, false, 1);
        write_json_field_string(output, "process", event->process, false, 1);
        write_json_field_string(output, "exe", event->exe, false, 1);
        write_json_field_string(output, "cmdline", event->cmdline, true, 1);
    }
    
    return 0;
}

/**
 * Write a process_exit event as JSON
 * Requirement: 10.1 - Valid JSON for all event types
 */
static int write_process_exit_event_json(FILE *output, processed_event_t *event, bool compact) {
    char *escaped = NULL;
    
    if (!output || !event) {
        return -1;
    }
    
    if (compact) {
        /* Compact format for json-stream */
        fprintf(output, "\"event_type\":\"process_exit\",");
        
        if (event->timestamp) {
            escaped = json_escape_string(event->timestamp);
            fprintf(output, "\"timestamp\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        }
        
        fprintf(output, "\"pid\":%u,\"uid\":%u,", event->pid, event->uid);
        
        if (event->process) {
            escaped = json_escape_string(event->process);
            fprintf(output, "\"process\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"process\":null,");
        }
        
        fprintf(output, "\"exit_code\":%d", event->exit_code);
    } else {
        /* Pretty format */
        write_json_field_string(output, "event_type", event->event_type, false, 1);
        write_json_field_string(output, "timestamp", event->timestamp, false, 1);
        write_json_field_uint(output, "pid", event->pid, false, 1);
        write_json_field_uint(output, "uid", event->uid, false, 1);
        write_json_field_string(output, "process", event->process, false, 1);
        write_json_field_int(output, "exit_code", event->exit_code, true, 1);
    }
    
    return 0;
}

/**
 * Write an api_call event as JSON
 * Requirement: 10.1 - Valid JSON for all event types
 */
static int write_api_call_event_json(FILE *output, processed_event_t *event, bool compact) {
    char *escaped = NULL;
    
    if (!output || !event) {
        return -1;
    }
    
    if (compact) {
        /* Compact format for json-stream */
        fprintf(output, "\"event_type\":\"api_call\",");
        
        if (event->timestamp) {
            escaped = json_escape_string(event->timestamp);
            fprintf(output, "\"timestamp\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        }
        
        fprintf(output, "\"pid\":%u,\"uid\":%u,", event->pid, event->uid);
        
        if (event->process) {
            escaped = json_escape_string(event->process);
            fprintf(output, "\"process\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"process\":null,");
        }
        
        if (event->exe) {
            escaped = json_escape_string(event->exe);
            fprintf(output, "\"exe\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"exe\":null,");
        }
        
        if (event->function_name) {
            escaped = json_escape_string(event->function_name);
            fprintf(output, "\"function_name\":\"%s\",", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"function_name\":null,");
        }
        
        if (event->library) {
            escaped = json_escape_string(event->library);
            fprintf(output, "\"library\":\"%s\"", escaped ? escaped : "");
            free(escaped);
        } else {
            fprintf(output, "\"library\":null");
        }
    } else {
        /* Pretty format */
        write_json_field_string(output, "event_type", event->event_type, false, 1);
        write_json_field_string(output, "timestamp", event->timestamp, false, 1);
        write_json_field_uint(output, "pid", event->pid, false, 1);
        write_json_field_uint(output, "uid", event->uid, false, 1);
        write_json_field_string(output, "process", event->process, false, 1);
        write_json_field_string(output, "exe", event->exe, false, 1);
        write_json_field_string(output, "function_name", event->function_name, false, 1);
        write_json_field_string(output, "library", event->library, true, 1);
    }
    
    return 0;
}

/**
 * Write an event as JSON
 * Requirements: 10.1, 10.2, 10.3
 * 
 * @param fmt Output formatter
 * @param event Event to write
 * @return 0 on success, -1 on failure
 */
int output_formatter_write_event(output_formatter_t *fmt, processed_event_t *event) {
    int indent = 0;
    bool compact = false;
    
    if (!fmt || !fmt->output || !event || !event->event_type) {
        return -1;
    }
    
    /* Determine if we're using compact format */
    compact = (fmt->format == FORMAT_JSON_STREAM);
    
    /* For JSON array format, handle commas between events */
    if (fmt->format == FORMAT_JSON_ARRAY) {
        if (!fmt->first_event) {
            fprintf(fmt->output, ",\n");
        }
        fmt->first_event = false;
        indent = 1;  /* Indent for array elements */
    }
    
    /* Start JSON object */
    if (fmt->format == FORMAT_JSON_PRETTY || fmt->format == FORMAT_JSON_ARRAY) {
        int i;
        for (i = 0; i < indent; i++) {
            fprintf(fmt->output, "  ");
        }
        fprintf(fmt->output, "{\n");
    } else {
        /* json-stream format: compact, one line per event */
        fprintf(fmt->output, "{");
    }
    
    /* Write event fields based on event type */
    if (strcmp(event->event_type, "file_open") == 0) {
        write_file_open_event_json(fmt->output, event, compact);
    } else if (strcmp(event->event_type, "lib_load") == 0) {
        write_lib_load_event_json(fmt->output, event, compact);
    } else if (strcmp(event->event_type, "process_exec") == 0) {
        write_process_exec_event_json(fmt->output, event, compact);
    } else if (strcmp(event->event_type, "process_exit") == 0) {
        write_process_exit_event_json(fmt->output, event, compact);
    } else if (strcmp(event->event_type, "api_call") == 0) {
        write_api_call_event_json(fmt->output, event, compact);
    } else {
        /* Unknown event type */
        return -1;
    }
    
    /* Close JSON object */
    if (fmt->format == FORMAT_JSON_PRETTY || fmt->format == FORMAT_JSON_ARRAY) {
        int i;
        for (i = 0; i < indent; i++) {
            fprintf(fmt->output, "  ");
        }
        fprintf(fmt->output, "}");
    } else {
        /* json-stream format */
        fprintf(fmt->output, "}");
    }
    
    /* For json-stream, add newline after each event */
    if (fmt->format == FORMAT_JSON_STREAM) {
        fprintf(fmt->output, "\n");
    }
    
    /* Flush output to ensure data is written */
    fflush(fmt->output);
    
    return 0;
}

/**
 * Write a profile document as JSON
 * Requirement: 2.2, 2.5, 10.6
 * 
 * @param fmt Output formatter
 * @param profile Profile to write
 * @return 0 on success, -1 on failure
 */
int output_formatter_write_profile(output_formatter_t *fmt, profile_t *profile) {
    size_t i;
    bool pretty = (fmt->format == FORMAT_JSON_PRETTY);
    int indent = pretty ? 1 : 0;
    
    if (!fmt || !fmt->output || !profile) {
        return -1;
    }
    
    /* Start profile object */
    fprintf(fmt->output, "{\n");
    
    /* Profile metadata */
    write_json_field_string(fmt->output, "profile_version", profile->profile_version, false, indent);
    write_json_field_string(fmt->output, "generated_at", profile->generated_at, false, indent);
    write_json_field_int(fmt->output, "duration_seconds", profile->duration_seconds, false, indent);
    
    /* Process information */
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "\"process\": {\n");
    write_json_field_uint(fmt->output, "pid", profile->process.pid, false, indent + 1);
    write_json_field_string(fmt->output, "name", profile->process.name, false, indent + 1);
    write_json_field_string(fmt->output, "exe", profile->process.exe, false, indent + 1);
    write_json_field_string(fmt->output, "cmdline", profile->process.cmdline, false, indent + 1);
    write_json_field_uint(fmt->output, "uid", profile->process.uid, false, indent + 1);
    write_json_field_uint(fmt->output, "gid", profile->process.gid, false, indent + 1);
    write_json_field_string(fmt->output, "start_time", profile->process.start_time, true, indent + 1);
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "},\n");
    
    /* Libraries array */
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "\"libraries\": [\n");
    for (i = 0; i < profile->library_count; i++) {
        if (pretty) fprintf(fmt->output, "    ");
        fprintf(fmt->output, "{\n");
        write_json_field_string(fmt->output, "name", profile->libraries[i].name, false, indent + 2);
        write_json_field_string(fmt->output, "path", profile->libraries[i].path, false, indent + 2);
        write_json_field_string(fmt->output, "load_time", profile->libraries[i].load_time, true, indent + 2);
        if (pretty) fprintf(fmt->output, "    ");
        fprintf(fmt->output, "}");
        if (i < profile->library_count - 1) {
            fprintf(fmt->output, ",");
        }
        fprintf(fmt->output, "\n");
    }
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "],\n");
    
    /* Files accessed array */
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "\"files_accessed\": [\n");
    for (i = 0; i < profile->file_count; i++) {
        if (pretty) fprintf(fmt->output, "    ");
        fprintf(fmt->output, "{\n");
        write_json_field_string(fmt->output, "path", profile->files_accessed[i].path, false, indent + 2);
        write_json_field_string(fmt->output, "type", profile->files_accessed[i].type, false, indent + 2);
        write_json_field_int(fmt->output, "access_count", profile->files_accessed[i].access_count, false, indent + 2);
        write_json_field_string(fmt->output, "first_access", profile->files_accessed[i].first_access, false, indent + 2);
        write_json_field_string(fmt->output, "last_access", profile->files_accessed[i].last_access, false, indent + 2);
        write_json_field_string(fmt->output, "mode", profile->files_accessed[i].mode, true, indent + 2);
        if (pretty) fprintf(fmt->output, "    ");
        fprintf(fmt->output, "}");
        if (i < profile->file_count - 1) {
            fprintf(fmt->output, ",");
        }
        fprintf(fmt->output, "\n");
    }
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "],\n");
    
    /* API calls array */
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "\"api_calls\": [\n");
    for (i = 0; i < profile->api_call_count; i++) {
        if (pretty) fprintf(fmt->output, "    ");
        fprintf(fmt->output, "{\n");
        write_json_field_string(fmt->output, "function_name", profile->api_calls[i].function_name, false, indent + 2);
        write_json_field_int(fmt->output, "count", profile->api_calls[i].count, true, indent + 2);
        if (pretty) fprintf(fmt->output, "    ");
        fprintf(fmt->output, "}");
        if (i < profile->api_call_count - 1) {
            fprintf(fmt->output, ",");
        }
        fprintf(fmt->output, "\n");
    }
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "],\n");
    
    /* Statistics */
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "\"statistics\": {\n");
    write_json_field_int(fmt->output, "total_events", profile->statistics.total_events, false, indent + 1);
    write_json_field_int(fmt->output, "libraries_loaded", profile->statistics.libraries_loaded, false, indent + 1);
    write_json_field_int(fmt->output, "files_accessed", profile->statistics.files_accessed, false, indent + 1);
    write_json_field_int(fmt->output, "api_calls_made", profile->statistics.api_calls_made, true, indent + 1);
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "}\n");
    
    /* Close profile object */
    fprintf(fmt->output, "}\n");
    
    fflush(fmt->output);
    return 0;
}

/**
 * Write a snapshot document as JSON
 * Requirement: 3.4, 10.6
 * 
 * @param fmt Output formatter
 * @param snapshot Snapshot to write
 * @return 0 on success, -1 on failure
 */
int output_formatter_write_snapshot(output_formatter_t *fmt, snapshot_t *snapshot) {
    char *escaped = NULL;
    size_t i, j;
    bool pretty = (fmt->format == FORMAT_JSON_PRETTY);
    int indent = pretty ? 1 : 0;
    
    if (!fmt || !fmt->output || !snapshot) {
        return -1;
    }
    
    /* Start snapshot object */
    fprintf(fmt->output, "{\n");
    
    /* Snapshot metadata */
    write_json_field_string(fmt->output, "snapshot_version", snapshot->snapshot_version, false, indent);
    write_json_field_string(fmt->output, "generated_at", snapshot->generated_at, false, indent);
    write_json_field_string(fmt->output, "hostname", snapshot->hostname, false, indent);
    write_json_field_string(fmt->output, "kernel", snapshot->kernel, false, indent);
    
    /* Processes array */
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "\"processes\": [\n");
    for (i = 0; i < snapshot->process_count; i++) {
        if (pretty) fprintf(fmt->output, "    ");
        fprintf(fmt->output, "{\n");
        write_json_field_uint(fmt->output, "pid", snapshot->processes[i].pid, false, indent + 2);
        write_json_field_string(fmt->output, "name", snapshot->processes[i].name, false, indent + 2);
        write_json_field_string(fmt->output, "exe", snapshot->processes[i].exe, false, indent + 2);
        write_json_field_string(fmt->output, "running_as", snapshot->processes[i].running_as, false, indent + 2);
        
        /* Libraries array for this process */
        if (pretty) fprintf(fmt->output, "      ");
        fprintf(fmt->output, "\"libraries\": [");
        for (j = 0; j < snapshot->processes[i].library_count; j++) {
            escaped = json_escape_string(snapshot->processes[i].libraries[j]);
            fprintf(fmt->output, "\"%s\"", escaped ? escaped : "");
            free(escaped);
            if (j < snapshot->processes[i].library_count - 1) {
                fprintf(fmt->output, ", ");
            }
        }
        fprintf(fmt->output, "],\n");
        
        /* Open crypto files array for this process */
        if (pretty) fprintf(fmt->output, "      ");
        fprintf(fmt->output, "\"open_crypto_files\": [");
        for (j = 0; j < snapshot->processes[i].file_count; j++) {
            escaped = json_escape_string(snapshot->processes[i].open_crypto_files[j]);
            fprintf(fmt->output, "\"%s\"", escaped ? escaped : "");
            free(escaped);
            if (j < snapshot->processes[i].file_count - 1) {
                fprintf(fmt->output, ", ");
            }
        }
        fprintf(fmt->output, "]\n");
        
        if (pretty) fprintf(fmt->output, "    ");
        fprintf(fmt->output, "}");
        if (i < snapshot->process_count - 1) {
            fprintf(fmt->output, ",");
        }
        fprintf(fmt->output, "\n");
    }
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "],\n");
    
    /* Summary */
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "\"summary\": {\n");
    write_json_field_int(fmt->output, "total_processes", snapshot->summary.total_processes, false, indent + 1);
    write_json_field_int(fmt->output, "total_libraries", snapshot->summary.total_libraries, false, indent + 1);
    write_json_field_int(fmt->output, "total_files", snapshot->summary.total_files, true, indent + 1);
    if (pretty) fprintf(fmt->output, "  ");
    fprintf(fmt->output, "}\n");
    
    /* Close snapshot object */
    fprintf(fmt->output, "}\n");
    
    fflush(fmt->output);
    return 0;
}
