// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_profile_snapshot.c - Unit tests for profile and snapshot JSON generation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include "../../src/include/output_formatter.h"
#include "../../src/include/event_processor.h"

int main(void) {
    output_formatter_t *fmt = NULL;
    FILE *output = NULL;
    profile_t profile = {0};
    snapshot_t snapshot = {0};
    char buffer[8192];
    size_t bytes_read;
    int tests_passed = 0;
    int tests_failed = 0;
    
    printf("Testing profile and snapshot JSON generation...\n\n");
    
    /* Test 1: Profile JSON generation */
    printf("Test 1: Profile JSON generation\n");
    output = tmpfile();
    if (!output) {
        printf("  FAIL: Could not create temp file\n");
        tests_failed++;
        goto test2;
    }
    
    fmt = output_formatter_create(FORMAT_JSON_PRETTY, output);
    if (!fmt) {
        printf("  FAIL: Could not create formatter\n");
        fclose(output);
        tests_failed++;
        goto test2;
    }
    
    /* Create test profile */
    profile.profile_version = "1.0";
    profile.generated_at = "2021-01-01T00:00:00.000000Z";
    profile.duration_seconds = 30;
    profile.process.pid = 1234;
    profile.process.name = "test_app";
    profile.process.exe = "/usr/bin/test_app";
    profile.process.cmdline = "/usr/bin/test_app --config test.conf";
    profile.process.uid = 1000;
    profile.process.gid = 1000;
    profile.process.start_time = "2021-01-01T00:00:00.000000Z";
    
    profile.library_count = 1;
    profile.libraries = calloc(1, sizeof(*profile.libraries));
    profile.libraries[0].name = "libssl";
    profile.libraries[0].path = "/usr/lib/libssl.so.1.1";
    profile.libraries[0].load_time = "2021-01-01T00:00:01.000000Z";
    
    profile.file_count = 0;
    profile.files_accessed = NULL;
    profile.api_call_count = 0;
    profile.api_calls = NULL;
    
    profile.statistics.total_events = 1;
    profile.statistics.libraries_loaded = 1;
    profile.statistics.files_accessed = 0;
    profile.statistics.api_calls_made = 0;
    
    if (output_formatter_write_profile(fmt, &profile) != 0) {
        printf("  FAIL: Could not write profile\n");
        tests_failed++;
    } else {
        rewind(output);
        bytes_read = fread(buffer, 1, sizeof(buffer) - 1, output);
        buffer[bytes_read] = '\0';
        
        if (strstr(buffer, "\"profile_version\"") && 
            strstr(buffer, "\"process\"") &&
            strstr(buffer, "\"libraries\"") &&
            strstr(buffer, "\"statistics\"")) {
            printf("  PASS: Profile JSON generated correctly\n");
            tests_passed++;
        } else {
            printf("  FAIL: Profile JSON missing required fields\n");
            tests_failed++;
        }
    }
    
    free(profile.libraries);
    output_formatter_destroy(fmt);
    fclose(output);
    
test2:
    /* Test 2: Snapshot JSON generation */
    printf("Test 2: Snapshot JSON generation\n");
    output = tmpfile();
    if (!output) {
        printf("  FAIL: Could not create temp file\n");
        tests_failed++;
        goto done;
    }
    
    fmt = output_formatter_create(FORMAT_JSON_PRETTY, output);
    if (!fmt) {
        printf("  FAIL: Could not create formatter\n");
        fclose(output);
        tests_failed++;
        goto done;
    }
    
    /* Create test snapshot */
    snapshot.snapshot_version = "1.0";
    snapshot.generated_at = "2021-01-01T00:00:00.000000Z";
    snapshot.hostname = "test-host";
    snapshot.kernel = "5.15.0-generic";
    
    snapshot.process_count = 1;
    snapshot.processes = calloc(1, sizeof(*snapshot.processes));
    snapshot.processes[0].pid = 1234;
    snapshot.processes[0].name = "test_app";
    snapshot.processes[0].exe = "/usr/bin/test_app";
    snapshot.processes[0].running_as = "user";
    snapshot.processes[0].library_count = 1;
    snapshot.processes[0].libraries = calloc(1, sizeof(char *));
    snapshot.processes[0].libraries[0] = "/usr/lib/libssl.so.1.1";
    snapshot.processes[0].file_count = 0;
    snapshot.processes[0].open_crypto_files = NULL;
    
    snapshot.summary.total_processes = 1;
    snapshot.summary.total_libraries = 1;
    snapshot.summary.total_files = 0;
    
    if (output_formatter_write_snapshot(fmt, &snapshot) != 0) {
        printf("  FAIL: Could not write snapshot\n");
        tests_failed++;
    } else {
        rewind(output);
        bytes_read = fread(buffer, 1, sizeof(buffer) - 1, output);
        buffer[bytes_read] = '\0';
        
        if (strstr(buffer, "\"snapshot_version\"") && 
            strstr(buffer, "\"hostname\"") &&
            strstr(buffer, "\"processes\"") &&
            strstr(buffer, "\"summary\"")) {
            printf("  PASS: Snapshot JSON generated correctly\n");
            tests_passed++;
        } else {
            printf("  FAIL: Snapshot JSON missing required fields\n");
            tests_failed++;
        }
    }
    
    free(snapshot.processes[0].libraries);
    free(snapshot.processes);
    output_formatter_destroy(fmt);
    fclose(output);
    
done:
    printf("\n=== Test Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    return (tests_failed == 0) ? 0 : 1;
}
