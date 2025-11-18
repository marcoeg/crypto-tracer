// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_privacy_filter.c - Unit tests for privacy filtering
 * Tests path redaction and privacy protection features
 * Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../src/include/privacy_filter.h"

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
 * Test: Home directory redaction
 * Requirement: 6.1 - /home/user/ → /home/USER/
 */
void test_home_directory_redaction(void) {
    TEST("test_home_directory_redaction");
    
    char *result = NULL;
    
    /* Test basic home directory redaction */
    result = privacy_filter_path("/home/alice/documents/cert.pem", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/home/USER/documents/cert.pem");
    free(result);
    
    /* Test different username */
    result = privacy_filter_path("/home/bob/.ssh/id_rsa", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/home/USER/.ssh/id_rsa");
    free(result);
    
    /* Test long username */
    result = privacy_filter_path("/home/verylongusername/file.key", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/home/USER/file.key");
    free(result);
    
    /* Test username without trailing slash */
    result = privacy_filter_path("/home/alice", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/home/USER");
    free(result);
    
    TEST_PASS();
}

/**
 * Test: Root directory redaction
 * Requirement: 6.2 - /root/ → /home/ROOT/
 */
void test_root_directory_redaction(void) {
    TEST("test_root_directory_redaction");
    
    char *result = NULL;
    
    /* Test basic root directory redaction */
    result = privacy_filter_path("/root/.ssh/id_rsa", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/home/ROOT/.ssh/id_rsa");
    free(result);
    
    /* Test root with subdirectories */
    result = privacy_filter_path("/root/certs/server.pem", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/home/ROOT/certs/server.pem");
    free(result);
    
    /* Test /root without trailing slash */
    result = privacy_filter_path("/root", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/home/ROOT");
    free(result);
    
    TEST_PASS();
}

/**
 * Test: System paths preservation
 * Requirement: 6.3 - Preserve system paths (/etc/, /usr/, /lib/)
 */
void test_system_paths_preservation(void) {
    TEST("test_system_paths_preservation");
    
    char *result = NULL;
    
    /* Test /etc/ preservation */
    result = privacy_filter_path("/etc/ssl/certs/ca-certificates.crt", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/etc/ssl/certs/ca-certificates.crt");
    free(result);
    
    /* Test /usr/ preservation */
    result = privacy_filter_path("/usr/lib/ssl/openssl.cnf", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/usr/lib/ssl/openssl.cnf");
    free(result);
    
    /* Test /lib/ preservation */
    result = privacy_filter_path("/lib/x86_64-linux-gnu/libssl.so.1.1", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/lib/x86_64-linux-gnu/libssl.so.1.1");
    free(result);
    
    /* Test /lib64/ preservation */
    result = privacy_filter_path("/lib64/libcrypto.so.3", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/lib64/libcrypto.so.3");
    free(result);
    
    /* Test /var/lib/ preservation */
    result = privacy_filter_path("/var/lib/ssl/private/key.pem", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/var/lib/ssl/private/key.pem");
    free(result);
    
    /* Test /opt/ preservation */
    result = privacy_filter_path("/opt/app/certs/cert.pem", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/opt/app/certs/cert.pem");
    free(result);
    
    /* Test /tmp/ preservation */
    result = privacy_filter_path("/tmp/temp-cert.pem", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/tmp/temp-cert.pem");
    free(result);
    
    TEST_PASS();
}

/**
 * Test: --no-redact flag disables redaction
 * Requirement: 6.4 - --no-redact flag disables all privacy filtering
 */
void test_no_redact_flag(void) {
    TEST("test_no_redact_flag");
    
    char *result = NULL;
    
    /* Test home directory with redaction disabled */
    result = privacy_filter_path("/home/alice/documents/cert.pem", false);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/home/alice/documents/cert.pem");
    free(result);
    
    /* Test root directory with redaction disabled */
    result = privacy_filter_path("/root/.ssh/id_rsa", false);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/root/.ssh/id_rsa");
    free(result);
    
    /* Test system path with redaction disabled (should still be unchanged) */
    result = privacy_filter_path("/etc/ssl/certs/ca-cert.crt", false);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/etc/ssl/certs/ca-cert.crt");
    free(result);
    
    TEST_PASS();
}

/**
 * Test: Command line filtering
 * Requirement: 6.5, 6.6 - Never log sensitive data
 */
void test_cmdline_filtering(void) {
    TEST("test_cmdline_filtering");
    
    char *result = NULL;
    
    /* Test basic command line (currently no sanitization) */
    result = privacy_filter_cmdline("openssl s_client -connect example.com:443", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "openssl s_client -connect example.com:443");
    free(result);
    
    /* Test with redaction disabled */
    result = privacy_filter_cmdline("openssl s_client -connect example.com:443", false);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "openssl s_client -connect example.com:443");
    free(result);
    
    TEST_PASS();
}

/**
 * Test: NULL input handling
 */
void test_null_input_handling(void) {
    TEST("test_null_input_handling");
    
    char *result = NULL;
    
    /* Test NULL path */
    result = privacy_filter_path(NULL, true);
    assert(result == NULL);
    
    /* Test NULL cmdline */
    result = privacy_filter_cmdline(NULL, true);
    assert(result == NULL);
    
    TEST_PASS();
}

/**
 * Test: Edge cases
 */
void test_edge_cases(void) {
    TEST("test_edge_cases");
    
    char *result = NULL;
    
    /* Test empty string */
    result = privacy_filter_path("", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "");
    free(result);
    
    /* Test path that looks like home but isn't */
    result = privacy_filter_path("/homestead/user/file.pem", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/homestead/user/file.pem");
    free(result);
    
    /* Test path that looks like root but isn't */
    result = privacy_filter_path("/rooted/file.pem", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/rooted/file.pem");
    free(result);
    
    /* Test relative path */
    result = privacy_filter_path("./cert.pem", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "./cert.pem");
    free(result);
    
    /* Test path without leading slash */
    result = privacy_filter_path("home/alice/cert.pem", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "home/alice/cert.pem");
    free(result);
    
    TEST_PASS();
}

/**
 * Test: Multiple path components
 */
void test_multiple_path_components(void) {
    TEST("test_multiple_path_components");
    
    char *result = NULL;
    
    /* Test deep home directory path */
    result = privacy_filter_path("/home/alice/work/project/certs/server.pem", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/home/USER/work/project/certs/server.pem");
    free(result);
    
    /* Test deep root directory path */
    result = privacy_filter_path("/root/backup/2024/certs/key.pem", true);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "/home/ROOT/backup/2024/certs/key.pem");
    free(result);
    
    TEST_PASS();
}

/**
 * Main test runner
 */
int main(void) {
    printf("=== Privacy Filter Unit Tests ===\n\n");
    
    /* Run all tests */
    test_home_directory_redaction();
    test_root_directory_redaction();
    test_system_paths_preservation();
    test_no_redact_flag();
    test_cmdline_filtering();
    test_null_input_handling();
    test_edge_cases();
    test_multiple_path_components();
    
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
