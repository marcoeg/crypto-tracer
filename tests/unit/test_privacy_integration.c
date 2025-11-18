// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_privacy_integration.c - Integration tests for privacy filtering with event processor
 * Tests that privacy filtering is properly integrated into the event processing pipeline
 * Requirements: 6.1, 6.2, 6.3, 6.4
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../src/include/event_processor.h"
#include "../../src/include/crypto_tracer.h"

/* Test counter */
static int tests_passed = 0;
static int tests_failed = 0;

/* Test helper macros */
#define TEST(name) \
    do { \
        printf("Running test: %s\n", name); \
    } while (0)

#define ASSERT_STR_EQ(actual, expected) \
    do { \
        if (strcmp(actual, expected) != 0) { \
            printf("  FAILED: Expected '%s', got '%s'\n", expected, actual); \
            tests_failed++; \
            return; \
        } \
    } while (0)

#define ASSERT_NOT_NULL(ptr) \
    do { \
        if (ptr == NULL) { \
            printf("  FAILED: Expected non-NULL pointer\n"); \
            tests_failed++; \
            return; \
        } \
    } while (0)

#define TEST_PASS() \
    do { \
        printf("  PASSED\n"); \
        tests_passed++; \
    } while (0)

/**
 * Test: Privacy filter integration with file events
 */
void test_privacy_filter_file_event(void) {
    TEST("test_privacy_filter_file_event");
    
    /* Create a mock event with home directory path */
    processed_event_t event = {0};
    event.event_type = strdup("file_open");
    event.file = strdup("/home/alice/documents/cert.pem");
    event.exe = strdup("/home/alice/bin/myapp");
    event.pid = 1234;
    event.uid = 1000;
    
    /* Apply privacy filter with redaction enabled */
    int result = apply_privacy_filter(&event, true);
    assert(result == 0);
    
    /* Verify paths are redacted */
    ASSERT_NOT_NULL(event.file);
    ASSERT_STR_EQ(event.file, "/home/USER/documents/cert.pem");
    
    ASSERT_NOT_NULL(event.exe);
    ASSERT_STR_EQ(event.exe, "/home/USER/bin/myapp");
    
    /* Cleanup */
    free(event.event_type);
    free(event.file);
    free(event.exe);
    
    TEST_PASS();
}

/**
 * Test: Privacy filter integration with library events
 */
void test_privacy_filter_library_event(void) {
    TEST("test_privacy_filter_library_event");
    
    /* Create a mock event with root directory path */
    processed_event_t event = {0};
    event.event_type = strdup("lib_load");
    event.library = strdup("/root/custom-libs/libcrypto.so");
    event.exe = strdup("/root/bin/server");
    event.pid = 5678;
    event.uid = 0;
    
    /* Apply privacy filter with redaction enabled */
    int result = apply_privacy_filter(&event, true);
    assert(result == 0);
    
    /* Verify paths are redacted */
    ASSERT_NOT_NULL(event.library);
    ASSERT_STR_EQ(event.library, "/home/ROOT/custom-libs/libcrypto.so");
    
    ASSERT_NOT_NULL(event.exe);
    ASSERT_STR_EQ(event.exe, "/home/ROOT/bin/server");
    
    /* Cleanup */
    free(event.event_type);
    free(event.library);
    free(event.exe);
    
    TEST_PASS();
}

/**
 * Test: Privacy filter preserves system paths
 */
void test_privacy_filter_system_paths(void) {
    TEST("test_privacy_filter_system_paths");
    
    /* Create a mock event with system paths */
    processed_event_t event = {0};
    event.event_type = strdup("file_open");
    event.file = strdup("/etc/ssl/certs/ca-certificates.crt");
    event.exe = strdup("/usr/bin/openssl");
    event.pid = 9999;
    event.uid = 0;
    
    /* Apply privacy filter with redaction enabled */
    int result = apply_privacy_filter(&event, true);
    assert(result == 0);
    
    /* Verify system paths are preserved */
    ASSERT_NOT_NULL(event.file);
    ASSERT_STR_EQ(event.file, "/etc/ssl/certs/ca-certificates.crt");
    
    ASSERT_NOT_NULL(event.exe);
    ASSERT_STR_EQ(event.exe, "/usr/bin/openssl");
    
    /* Cleanup */
    free(event.event_type);
    free(event.file);
    free(event.exe);
    
    TEST_PASS();
}

/**
 * Test: Privacy filter disabled with --no-redact
 */
void test_privacy_filter_disabled(void) {
    TEST("test_privacy_filter_disabled");
    
    /* Create a mock event with home directory path */
    processed_event_t event = {0};
    event.event_type = strdup("file_open");
    event.file = strdup("/home/bob/secrets/private.key");
    event.exe = strdup("/home/bob/app");
    event.pid = 1111;
    event.uid = 1001;
    
    /* Apply privacy filter with redaction DISABLED */
    int result = apply_privacy_filter(&event, false);
    assert(result == 0);
    
    /* Verify paths are NOT redacted */
    ASSERT_NOT_NULL(event.file);
    ASSERT_STR_EQ(event.file, "/home/bob/secrets/private.key");
    
    ASSERT_NOT_NULL(event.exe);
    ASSERT_STR_EQ(event.exe, "/home/bob/app");
    
    /* Cleanup */
    free(event.event_type);
    free(event.file);
    free(event.exe);
    
    TEST_PASS();
}

/**
 * Test: Privacy filter with command line
 */
void test_privacy_filter_cmdline(void) {
    TEST("test_privacy_filter_cmdline");
    
    /* Create a mock event with command line */
    processed_event_t event = {0};
    event.event_type = strdup("process_exec");
    event.cmdline = strdup("openssl s_client -connect example.com:443");
    event.exe = strdup("/usr/bin/openssl");
    event.pid = 2222;
    event.uid = 1000;
    
    /* Apply privacy filter with redaction enabled */
    int result = apply_privacy_filter(&event, true);
    assert(result == 0);
    
    /* Verify command line is preserved (no sanitization in v1.0) */
    ASSERT_NOT_NULL(event.cmdline);
    ASSERT_STR_EQ(event.cmdline, "openssl s_client -connect example.com:443");
    
    /* Cleanup */
    free(event.event_type);
    free(event.cmdline);
    free(event.exe);
    
    TEST_PASS();
}

/**
 * Test: Privacy filter with NULL fields
 */
void test_privacy_filter_null_fields(void) {
    TEST("test_privacy_filter_null_fields");
    
    /* Create a mock event with some NULL fields */
    processed_event_t event = {0};
    event.event_type = strdup("process_exit");
    event.file = NULL;
    event.library = NULL;
    event.exe = NULL;
    event.cmdline = NULL;
    event.pid = 3333;
    event.uid = 1000;
    
    /* Apply privacy filter - should not crash */
    int result = apply_privacy_filter(&event, true);
    assert(result == 0);
    
    /* Verify NULL fields remain NULL */
    assert(event.file == NULL);
    assert(event.library == NULL);
    assert(event.exe == NULL);
    assert(event.cmdline == NULL);
    
    /* Cleanup */
    free(event.event_type);
    
    TEST_PASS();
}

/**
 * Main test runner
 */
int main(void) {
    printf("=== Privacy Filter Integration Tests ===\n\n");
    
    /* Run all tests */
    test_privacy_filter_file_event();
    test_privacy_filter_library_event();
    test_privacy_filter_system_paths();
    test_privacy_filter_disabled();
    test_privacy_filter_cmdline();
    test_privacy_filter_null_fields();
    
    /* Print summary */
    printf("\n=== Test Summary ===\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    
    if (tests_failed > 0) {
        printf("\nSome tests FAILED!\n");
        return 1;
    }
    
    printf("\nAll tests PASSED!\n");
    return 0;
}
