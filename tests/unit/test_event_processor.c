// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_event_processor.c - Unit tests for event processor
 * Tests filtering, pattern matching, and filter evaluation
 */

/* Enable POSIX features for strdup */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "../../src/include/crypto_tracer.h"
#include "../../src/include/event_processor.h"

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;

/* Forward declarations */
static int test_glob_match(void);
static int test_substring_match(void);
static int test_filter_set_lifecycle(void);
static int test_filter_set_add(void);
static int test_pid_filter(void);
static int test_process_name_filter(void);
static int test_library_filter(void);
static int test_file_path_filter(void);
static int test_multiple_filters_and_logic(void);
static int test_empty_filter_set(void);
static int test_event_processor_create(void);
static int test_enrich_process_name(void);
static int test_enrich_executable_path(void);
static int test_enrich_cmdline(void);
static int test_enrich_event(void);
static int test_classify_crypto_file(void);
static int test_file_type_to_string(void);
static int test_extract_library_name(void);

#define TEST(name) \
    do { \
        printf("Running test: %s\n", name); \
        tests_run++; \
    } while (0)

#define ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("  FAILED: %s\n", message); \
            return -1; \
        } \
    } while (0)

#define TEST_PASS() \
    do { \
        printf("  PASSED\n"); \
        tests_passed++; \
        return 0; \
    } while (0)

/**
 * Test glob pattern matching
 */
static int test_glob_match(void) {
    TEST("glob_match");
    
    /* Exact match */
    ASSERT(glob_match("/etc/ssl/cert.pem", "/etc/ssl/cert.pem"), 
           "Exact match should succeed");
    
    /* Wildcard match */
    ASSERT(glob_match("/etc/ssl/*.pem", "/etc/ssl/cert.pem"), 
           "Wildcard match should succeed");
    ASSERT(glob_match("/etc/ssl/*.pem", "/etc/ssl/key.pem"), 
           "Wildcard match should succeed for different file");
    
    /* No match */
    ASSERT(!glob_match("/etc/ssl/*.pem", "/etc/ssl/cert.crt"), 
           "Non-matching extension should fail");
    ASSERT(!glob_match("/etc/ssl/*.pem", "/var/ssl/cert.pem"), 
           "Non-matching directory should fail");
    
    /* Multiple wildcards */
    ASSERT(glob_match("/etc/*/*.pem", "/etc/ssl/cert.pem"), 
           "Multiple wildcards should work");
    
    /* NULL handling */
    ASSERT(!glob_match(NULL, "/etc/ssl/cert.pem"), 
           "NULL pattern should return false");
    ASSERT(!glob_match("/etc/ssl/*.pem", NULL), 
           "NULL string should return false");
    
    TEST_PASS();
}

/**
 * Test substring matching
 */
static int test_substring_match(void) {
    TEST("substring_match");
    
    /* Exact match */
    ASSERT(substring_match("nginx", "nginx"), 
           "Exact match should succeed");
    
    /* Substring match */
    ASSERT(substring_match("nginx", "/usr/sbin/nginx"), 
           "Substring match should succeed");
    ASSERT(substring_match("ssl", "libssl.so.1.1"), 
           "Substring in library name should match");
    
    /* Case-insensitive */
    ASSERT(substring_match("NGINX", "nginx"), 
           "Case-insensitive match should succeed");
    ASSERT(substring_match("nginx", "NGINX"), 
           "Case-insensitive match should succeed (reversed)");
    ASSERT(substring_match("SsL", "libssl.so"), 
           "Mixed case should match");
    
    /* No match */
    ASSERT(!substring_match("apache", "nginx"), 
           "Non-matching string should fail");
    ASSERT(!substring_match("nginx", "apache"), 
           "Non-matching string should fail (reversed)");
    
    /* Empty pattern */
    ASSERT(substring_match("", "anything"), 
           "Empty pattern should match everything");
    
    /* NULL handling */
    ASSERT(!substring_match(NULL, "nginx"), 
           "NULL pattern should return false");
    ASSERT(!substring_match("nginx", NULL), 
           "NULL string should return false");
    
    TEST_PASS();
}

/**
 * Test filter set creation and destruction
 */
static int test_filter_set_lifecycle(void) {
    TEST("filter_set_lifecycle");
    
    filter_set_t *set = filter_set_create();
    ASSERT(set != NULL, "Filter set creation should succeed");
    ASSERT(set->count == 0, "New filter set should have count 0");
    ASSERT(set->filters == NULL, "New filter set should have NULL filters");
    
    filter_set_destroy(set);
    
    /* NULL handling */
    filter_set_destroy(NULL);  /* Should not crash */
    
    TEST_PASS();
}

/**
 * Test adding filters to filter set
 */
static int test_filter_set_add(void) {
    TEST("filter_set_add");
    
    filter_set_t *set = filter_set_create();
    ASSERT(set != NULL, "Filter set creation should succeed");
    
    /* Add PID filter */
    int pid = 1234;
    ASSERT(filter_set_add(set, FILTER_TYPE_PID, &pid) == 0, 
           "Adding PID filter should succeed");
    ASSERT(set->count == 1, "Filter count should be 1");
    
    /* Add process name filter */
    ASSERT(filter_set_add(set, FILTER_TYPE_PROCESS_NAME, "nginx") == 0, 
           "Adding process name filter should succeed");
    ASSERT(set->count == 2, "Filter count should be 2");
    
    /* Add library filter */
    ASSERT(filter_set_add(set, FILTER_TYPE_LIBRARY, "libssl") == 0, 
           "Adding library filter should succeed");
    ASSERT(set->count == 3, "Filter count should be 3");
    
    /* Add file path filter */
    ASSERT(filter_set_add(set, FILTER_TYPE_FILE_PATH, "/etc/ssl/*.pem") == 0, 
           "Adding file path filter should succeed");
    ASSERT(set->count == 4, "Filter count should be 4");
    
    filter_set_destroy(set);
    
    TEST_PASS();
}

/**
 * Test PID filter matching
 */
static int test_pid_filter(void) {
    TEST("pid_filter");
    
    filter_set_t *set = filter_set_create();
    int pid = 1234;
    filter_set_add(set, FILTER_TYPE_PID, &pid);
    
    /* Create test event */
    processed_event_t event = {0};
    event.pid = 1234;
    event.process = strdup("test");
    
    /* Should match */
    ASSERT(filter_set_matches(set, &event), 
           "Event with matching PID should pass filter");
    
    /* Should not match */
    event.pid = 5678;
    ASSERT(!filter_set_matches(set, &event), 
           "Event with non-matching PID should fail filter");
    
    free(event.process);
    filter_set_destroy(set);
    
    TEST_PASS();
}

/**
 * Test process name filter matching
 */
static int test_process_name_filter(void) {
    TEST("process_name_filter");
    
    filter_set_t *set = filter_set_create();
    filter_set_add(set, FILTER_TYPE_PROCESS_NAME, "nginx");
    
    /* Create test event */
    processed_event_t event = {0};
    
    /* Should match - exact */
    event.process = strdup("nginx");
    ASSERT(filter_set_matches(set, &event), 
           "Event with exact process name should pass filter");
    free(event.process);
    
    /* Should match - substring */
    event.process = strdup("/usr/sbin/nginx");
    ASSERT(filter_set_matches(set, &event), 
           "Event with process name substring should pass filter");
    free(event.process);
    
    /* Should match - case insensitive */
    event.process = strdup("NGINX");
    ASSERT(filter_set_matches(set, &event), 
           "Event with case-insensitive match should pass filter");
    free(event.process);
    
    /* Should not match */
    event.process = strdup("apache");
    ASSERT(!filter_set_matches(set, &event), 
           "Event with non-matching process name should fail filter");
    free(event.process);
    
    filter_set_destroy(set);
    
    TEST_PASS();
}

/**
 * Test library filter matching
 */
static int test_library_filter(void) {
    TEST("library_filter");
    
    filter_set_t *set = filter_set_create();
    filter_set_add(set, FILTER_TYPE_LIBRARY, "libssl");
    
    /* Create test event */
    processed_event_t event = {0};
    
    /* Should match - library path */
    event.library = strdup("/usr/lib/libssl.so.1.1");
    ASSERT(filter_set_matches(set, &event), 
           "Event with matching library path should pass filter");
    free(event.library);
    event.library = NULL;
    
    /* Should match - library name */
    event.library_name = strdup("libssl");
    ASSERT(filter_set_matches(set, &event), 
           "Event with matching library name should pass filter");
    free(event.library_name);
    event.library_name = NULL;
    
    /* Should not match */
    event.library = strdup("/usr/lib/libcrypto.so");
    ASSERT(!filter_set_matches(set, &event), 
           "Event with non-matching library should fail filter");
    free(event.library);
    
    filter_set_destroy(set);
    
    TEST_PASS();
}

/**
 * Test file path filter matching
 */
static int test_file_path_filter(void) {
    TEST("file_path_filter");
    
    filter_set_t *set = filter_set_create();
    filter_set_add(set, FILTER_TYPE_FILE_PATH, "/etc/ssl/*.pem");
    
    /* Create test event */
    processed_event_t event = {0};
    
    /* Should match */
    event.file = strdup("/etc/ssl/cert.pem");
    ASSERT(filter_set_matches(set, &event), 
           "Event with matching file path should pass filter");
    free(event.file);
    
    event.file = strdup("/etc/ssl/key.pem");
    ASSERT(filter_set_matches(set, &event), 
           "Event with matching file path (different file) should pass filter");
    free(event.file);
    
    /* Should not match */
    event.file = strdup("/etc/ssl/cert.crt");
    ASSERT(!filter_set_matches(set, &event), 
           "Event with non-matching extension should fail filter");
    free(event.file);
    
    event.file = strdup("/var/ssl/cert.pem");
    ASSERT(!filter_set_matches(set, &event), 
           "Event with non-matching directory should fail filter");
    free(event.file);
    
    filter_set_destroy(set);
    
    TEST_PASS();
}

/**
 * Test AND logic with multiple filters
 */
static int test_multiple_filters_and_logic(void) {
    TEST("multiple_filters_and_logic");
    
    filter_set_t *set = filter_set_create();
    int pid = 1234;
    filter_set_add(set, FILTER_TYPE_PID, &pid);
    filter_set_add(set, FILTER_TYPE_PROCESS_NAME, "nginx");
    
    /* Create test event */
    processed_event_t event = {0};
    
    /* Both filters match - should pass */
    event.pid = 1234;
    event.process = strdup("nginx");
    ASSERT(filter_set_matches(set, &event), 
           "Event matching all filters should pass");
    free(event.process);
    
    /* Only PID matches - should fail */
    event.pid = 1234;
    event.process = strdup("apache");
    ASSERT(!filter_set_matches(set, &event), 
           "Event matching only one filter should fail (AND logic)");
    free(event.process);
    
    /* Only process name matches - should fail */
    event.pid = 5678;
    event.process = strdup("nginx");
    ASSERT(!filter_set_matches(set, &event), 
           "Event matching only one filter should fail (AND logic, reversed)");
    free(event.process);
    
    /* Neither matches - should fail */
    event.pid = 5678;
    event.process = strdup("apache");
    ASSERT(!filter_set_matches(set, &event), 
           "Event matching no filters should fail");
    free(event.process);
    
    filter_set_destroy(set);
    
    TEST_PASS();
}

/**
 * Test empty filter set (should match everything)
 */
static int test_empty_filter_set(void) {
    TEST("empty_filter_set");
    
    filter_set_t *set = filter_set_create();
    
    /* Create test event */
    processed_event_t event = {0};
    event.pid = 1234;
    event.process = strdup("nginx");
    
    /* Empty filter set should match everything */
    ASSERT(filter_set_matches(set, &event), 
           "Empty filter set should match any event");
    
    free(event.process);
    filter_set_destroy(set);
    
    TEST_PASS();
}

/**
 * Test event processor creation with CLI args
 */
static int test_event_processor_create(void) {
    TEST("event_processor_create");
    
    cli_args_t args = {0};
    args.command = CMD_MONITOR;
    args.pid = 1234;
    args.process_name = "nginx";
    args.library_filter = "libssl";
    args.file_filter = "/etc/ssl/*.pem";
    args.no_redact = false;
    
    event_processor_t *proc = event_processor_create(&args);
    ASSERT(proc != NULL, "Event processor creation should succeed");
    ASSERT(proc->filters != NULL, "Event processor should have filters");
    ASSERT(proc->filters->count == 4, "Event processor should have 4 filters");
    ASSERT(proc->redact_paths == true, "Path redaction should be enabled by default");
    
    event_processor_destroy(proc);
    
    /* Test with no_redact flag */
    args.no_redact = true;
    proc = event_processor_create(&args);
    ASSERT(proc != NULL, "Event processor creation should succeed");
    ASSERT(proc->redact_paths == false, "Path redaction should be disabled with no_redact");
    
    event_processor_destroy(proc);
    
    TEST_PASS();
}

/**
 * Main test runner
 */
int main(void) {
    printf("=== Event Processor Unit Tests ===\n\n");
    
    /* Pattern matching tests */
    test_glob_match();
    test_substring_match();
    
    /* Filter set tests */
    test_filter_set_lifecycle();
    test_filter_set_add();
    
    /* Individual filter tests */
    test_pid_filter();
    test_process_name_filter();
    test_library_filter();
    test_file_path_filter();
    
    /* Multiple filter tests */
    test_multiple_filters_and_logic();
    test_empty_filter_set();
    
    /* Event processor tests */
    test_event_processor_create();
    
    /* Enrichment tests */
    test_enrich_process_name();
    test_enrich_executable_path();
    test_enrich_cmdline();
    test_enrich_event();
    
    /* Classification tests */
    test_classify_crypto_file();
    test_file_type_to_string();
    test_extract_library_name();
    
    printf("\n=== Test Summary ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    
    return (tests_run == tests_passed) ? 0 : 1;
}


/**
 * Test process name enrichment
 */
static int test_enrich_process_name(void) {
    TEST("enrich_process_name");
    
    char *process_name = NULL;
    
    /* Test with current process (should succeed) */
    pid_t my_pid = getpid();
    ASSERT(enrich_process_name(my_pid, &process_name) == 0, 
           "Enriching current process should succeed");
    ASSERT(process_name != NULL, 
           "Process name should not be NULL");
    ASSERT(strlen(process_name) > 0, 
           "Process name should not be empty");
    
    free(process_name);
    process_name = NULL;
    
    /* Test with invalid PID (should fail gracefully) */
    ASSERT(enrich_process_name(999999, &process_name) != 0, 
           "Enriching invalid PID should fail");
    ASSERT(process_name == NULL, 
           "Process name should be NULL on failure");
    
    /* Test with NULL output pointer */
    ASSERT(enrich_process_name(my_pid, NULL) != 0, 
           "NULL output pointer should fail");
    
    TEST_PASS();
}

/**
 * Test executable path enrichment
 */
static int test_enrich_executable_path(void) {
    TEST("enrich_executable_path");
    
    char *exe_path = NULL;
    
    /* Test with current process (should succeed) */
    pid_t my_pid = getpid();
    ASSERT(enrich_executable_path(my_pid, &exe_path) == 0, 
           "Enriching current process should succeed");
    ASSERT(exe_path != NULL, 
           "Executable path should not be NULL");
    ASSERT(strlen(exe_path) > 0, 
           "Executable path should not be empty");
    
    free(exe_path);
    exe_path = NULL;
    
    /* Test with invalid PID (should fail gracefully) */
    ASSERT(enrich_executable_path(999999, &exe_path) != 0, 
           "Enriching invalid PID should fail");
    ASSERT(exe_path == NULL, 
           "Executable path should be NULL on failure");
    
    /* Test with NULL output pointer */
    ASSERT(enrich_executable_path(my_pid, NULL) != 0, 
           "NULL output pointer should fail");
    
    TEST_PASS();
}

/**
 * Test command line enrichment
 */
static int test_enrich_cmdline(void) {
    TEST("enrich_cmdline");
    
    char *cmdline = NULL;
    
    /* Test with current process (should succeed) */
    pid_t my_pid = getpid();
    ASSERT(enrich_cmdline(my_pid, &cmdline) == 0, 
           "Enriching current process should succeed");
    ASSERT(cmdline != NULL, 
           "Command line should not be NULL");
    ASSERT(strlen(cmdline) > 0, 
           "Command line should not be empty");
    
    free(cmdline);
    cmdline = NULL;
    
    /* Test with invalid PID (should fail gracefully) */
    ASSERT(enrich_cmdline(999999, &cmdline) != 0, 
           "Enriching invalid PID should fail");
    ASSERT(cmdline == NULL, 
           "Command line should be NULL on failure");
    
    /* Test with NULL output pointer */
    ASSERT(enrich_cmdline(my_pid, NULL) != 0, 
           "NULL output pointer should fail");
    
    TEST_PASS();
}

/**
 * Test full event enrichment
 */
static int test_enrich_event(void) {
    TEST("enrich_event");
    
    processed_event_t event = {0};
    pid_t my_pid = getpid();
    
    /* Set up event with PID */
    event.pid = my_pid;
    event.event_type = strdup("file_open");
    
    /* Enrich event */
    ASSERT(enrich_event(&event) == 0, 
           "Event enrichment should succeed");
    
    /* Check that enrichment occurred */
    ASSERT(event.process != NULL, 
           "Process name should be enriched");
    ASSERT(event.exe != NULL, 
           "Executable path should be enriched");
    
    /* Clean up */
    free(event.event_type);
    free(event.process);
    free(event.exe);
    
    /* Test with invalid PID (should not crash) */
    memset(&event, 0, sizeof(event));
    event.pid = 999999;
    ASSERT(enrich_event(&event) == 0, 
           "Event enrichment with invalid PID should not crash");
    
    /* Test with NULL event */
    ASSERT(enrich_event(NULL) != 0, 
           "NULL event should fail");
    
    TEST_PASS();
}


/**
 * Test file classification
 */
static int test_classify_crypto_file(void) {
    TEST("classify_crypto_file");
    
    /* Certificate files */
    ASSERT(classify_crypto_file("/etc/ssl/cert.pem") == FILE_TYPE_CERTIFICATE, 
           ".pem should be classified as certificate");
    ASSERT(classify_crypto_file("/etc/ssl/cert.crt") == FILE_TYPE_CERTIFICATE, 
           ".crt should be classified as certificate");
    ASSERT(classify_crypto_file("/etc/ssl/cert.cer") == FILE_TYPE_CERTIFICATE, 
           ".cer should be classified as certificate");
    
    /* Private key files */
    ASSERT(classify_crypto_file("/etc/ssl/private.key") == FILE_TYPE_PRIVATE_KEY, 
           ".key should be classified as private_key");
    
    /* Keystore files */
    ASSERT(classify_crypto_file("/etc/ssl/keystore.p12") == FILE_TYPE_KEYSTORE, 
           ".p12 should be classified as keystore");
    ASSERT(classify_crypto_file("/etc/ssl/keystore.pfx") == FILE_TYPE_KEYSTORE, 
           ".pfx should be classified as keystore");
    ASSERT(classify_crypto_file("/etc/ssl/keystore.jks") == FILE_TYPE_KEYSTORE, 
           ".jks should be classified as keystore");
    ASSERT(classify_crypto_file("/etc/ssl/app.keystore") == FILE_TYPE_KEYSTORE, 
           ".keystore should be classified as keystore");
    
    /* Unknown files */
    ASSERT(classify_crypto_file("/etc/ssl/file.txt") == FILE_TYPE_UNKNOWN, 
           ".txt should be classified as unknown");
    ASSERT(classify_crypto_file("/etc/ssl/file") == FILE_TYPE_UNKNOWN, 
           "No extension should be classified as unknown");
    
    /* Case insensitive */
    ASSERT(classify_crypto_file("/etc/ssl/CERT.PEM") == FILE_TYPE_CERTIFICATE, 
           "Uppercase .PEM should be classified as certificate");
    ASSERT(classify_crypto_file("/etc/ssl/KEY.KEY") == FILE_TYPE_PRIVATE_KEY, 
           "Uppercase .KEY should be classified as private_key");
    
    /* NULL handling */
    ASSERT(classify_crypto_file(NULL) == FILE_TYPE_UNKNOWN, 
           "NULL path should return unknown");
    
    TEST_PASS();
}

/**
 * Test file type to string conversion
 */
static int test_file_type_to_string(void) {
    TEST("file_type_to_string");
    
    ASSERT(strcmp(file_type_to_string(FILE_TYPE_CERTIFICATE), "certificate") == 0, 
           "Certificate type should return 'certificate'");
    ASSERT(strcmp(file_type_to_string(FILE_TYPE_PRIVATE_KEY), "private_key") == 0, 
           "Private key type should return 'private_key'");
    ASSERT(strcmp(file_type_to_string(FILE_TYPE_KEYSTORE), "keystore") == 0, 
           "Keystore type should return 'keystore'");
    ASSERT(strcmp(file_type_to_string(FILE_TYPE_UNKNOWN), "unknown") == 0, 
           "Unknown type should return 'unknown'");
    
    TEST_PASS();
}

/**
 * Test library name extraction
 */
static int test_extract_library_name(void) {
    TEST("extract_library_name");
    
    char *name = NULL;
    
    /* Standard library paths */
    name = extract_library_name("/usr/lib/libssl.so.1.1");
    ASSERT(name != NULL, "Extraction should succeed");
    ASSERT(strcmp(name, "libssl") == 0, "Should extract 'libssl'");
    free(name);
    
    name = extract_library_name("/lib/x86_64-linux-gnu/libcrypto.so.3");
    ASSERT(name != NULL, "Extraction should succeed");
    ASSERT(strcmp(name, "libcrypto") == 0, "Should extract 'libcrypto'");
    free(name);
    
    name = extract_library_name("/usr/lib/libgnutls.so");
    ASSERT(name != NULL, "Extraction should succeed");
    ASSERT(strcmp(name, "libgnutls") == 0, "Should extract 'libgnutls'");
    free(name);
    
    /* Library without path */
    name = extract_library_name("libsodium.so.23");
    ASSERT(name != NULL, "Extraction should succeed");
    ASSERT(strcmp(name, "libsodium") == 0, "Should extract 'libsodium'");
    free(name);
    
    /* Library without version */
    name = extract_library_name("/usr/lib/libnss3");
    ASSERT(name != NULL, "Extraction should succeed");
    ASSERT(strcmp(name, "libnss3") == 0, "Should extract 'libnss3'");
    free(name);
    
    /* NULL handling */
    name = extract_library_name(NULL);
    ASSERT(name == NULL, "NULL path should return NULL");
    
    TEST_PASS();
}
