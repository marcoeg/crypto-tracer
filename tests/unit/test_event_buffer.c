// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_event_buffer.c - Unit tests for event buffer pool
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../src/include/crypto_tracer.h"

/* Test counter */
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        printf("Running test: %s ... ", name); \
        fflush(stdout); \
    } while(0)

#define PASS() \
    do { \
        printf("PASS\n"); \
        tests_passed++; \
    } while(0)

#define FAIL(msg) \
    do { \
        printf("FAIL: %s\n", msg); \
        tests_failed++; \
    } while(0)

/**
 * Test: Create and destroy event buffer pool
 */
void test_create_destroy(void) {
    TEST("create_destroy");
    
    event_buffer_pool_t *pool = event_buffer_pool_create(100);
    if (!pool) {
        FAIL("Failed to create pool");
        return;
    }
    
    if (pool->capacity != 100) {
        FAIL("Pool capacity incorrect");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    if (pool->in_use_count != 0) {
        FAIL("Initial in_use_count should be 0");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    event_buffer_pool_destroy(pool);
    PASS();
}

/**
 * Test: Acquire and release single event
 */
void test_acquire_release_single(void) {
    TEST("acquire_release_single");
    
    event_buffer_pool_t *pool = event_buffer_pool_create(10);
    if (!pool) {
        FAIL("Failed to create pool");
        return;
    }
    
    processed_event_t *event = event_buffer_pool_acquire(pool);
    if (!event) {
        FAIL("Failed to acquire event");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    if (pool->in_use_count != 1) {
        FAIL("in_use_count should be 1 after acquire");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    if (!event->in_use) {
        FAIL("Event should be marked as in_use");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    event_buffer_pool_release(pool, event);
    
    if (pool->in_use_count != 0) {
        FAIL("in_use_count should be 0 after release");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    event_buffer_pool_destroy(pool);
    PASS();
}

/**
 * Test: Acquire multiple events
 */
void test_acquire_multiple(void) {
    TEST("acquire_multiple");
    
    event_buffer_pool_t *pool = event_buffer_pool_create(10);
    if (!pool) {
        FAIL("Failed to create pool");
        return;
    }
    
    processed_event_t *events[5];
    int i;
    
    for (i = 0; i < 5; i++) {
        events[i] = event_buffer_pool_acquire(pool);
        if (!events[i]) {
            FAIL("Failed to acquire event");
            event_buffer_pool_destroy(pool);
            return;
        }
    }
    
    if (pool->in_use_count != 5) {
        FAIL("in_use_count should be 5");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    for (i = 0; i < 5; i++) {
        event_buffer_pool_release(pool, events[i]);
    }
    
    if (pool->in_use_count != 0) {
        FAIL("in_use_count should be 0 after releasing all");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    event_buffer_pool_destroy(pool);
    PASS();
}

/**
 * Test: Pool exhaustion
 */
void test_pool_exhaustion(void) {
    TEST("pool_exhaustion");
    
    event_buffer_pool_t *pool = event_buffer_pool_create(3);
    if (!pool) {
        FAIL("Failed to create pool");
        return;
    }
    
    processed_event_t *e1 = event_buffer_pool_acquire(pool);
    processed_event_t *e2 = event_buffer_pool_acquire(pool);
    processed_event_t *e3 = event_buffer_pool_acquire(pool);
    
    if (!e1 || !e2 || !e3) {
        FAIL("Failed to acquire events");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    /* Pool should be exhausted now */
    processed_event_t *e4 = event_buffer_pool_acquire(pool);
    if (e4 != NULL) {
        FAIL("Should return NULL when pool is exhausted");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    /* Release one and try again */
    event_buffer_pool_release(pool, e1);
    
    e4 = event_buffer_pool_acquire(pool);
    if (!e4) {
        FAIL("Should be able to acquire after release");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    event_buffer_pool_release(pool, e2);
    event_buffer_pool_release(pool, e3);
    event_buffer_pool_release(pool, e4);
    
    event_buffer_pool_destroy(pool);
    PASS();
}

/**
 * Test: Event data is cleared on acquire
 */
void test_event_cleared_on_acquire(void) {
    TEST("event_cleared_on_acquire");
    
    event_buffer_pool_t *pool = event_buffer_pool_create(10);
    if (!pool) {
        FAIL("Failed to create pool");
        return;
    }
    
    processed_event_t *event = event_buffer_pool_acquire(pool);
    if (!event) {
        FAIL("Failed to acquire event");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    /* Set some data */
    event->event_type = strdup("test_event");
    event->pid = 1234;
    event->uid = 5678;
    
    /* Release and re-acquire */
    event_buffer_pool_release(pool, event);
    event = event_buffer_pool_acquire(pool);
    
    if (!event) {
        FAIL("Failed to re-acquire event");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    /* Event should be cleared */
    if (event->event_type != NULL) {
        FAIL("event_type should be NULL after re-acquire");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    if (event->pid != 0) {
        FAIL("pid should be 0 after re-acquire");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    event_buffer_pool_release(pool, event);
    event_buffer_pool_destroy(pool);
    PASS();
}

/**
 * Test: Default capacity
 */
void test_default_capacity(void) {
    TEST("default_capacity");
    
    event_buffer_pool_t *pool = event_buffer_pool_create(0);
    if (!pool) {
        FAIL("Failed to create pool with default capacity");
        return;
    }
    
    if (pool->capacity != 1000) {
        FAIL("Default capacity should be 1000");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    event_buffer_pool_destroy(pool);
    PASS();
}

/**
 * Test: Large pool (1000 events as per requirement)
 */
void test_large_pool(void) {
    TEST("large_pool");
    
    event_buffer_pool_t *pool = event_buffer_pool_create(1000);
    if (!pool) {
        FAIL("Failed to create pool with 1000 events");
        return;
    }
    
    /* Acquire 100 events */
    processed_event_t *events[100];
    int i;
    
    for (i = 0; i < 100; i++) {
        events[i] = event_buffer_pool_acquire(pool);
        if (!events[i]) {
            FAIL("Failed to acquire event from large pool");
            event_buffer_pool_destroy(pool);
            return;
        }
    }
    
    if (pool->in_use_count != 100) {
        FAIL("in_use_count should be 100");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    /* Release all */
    for (i = 0; i < 100; i++) {
        event_buffer_pool_release(pool, events[i]);
    }
    
    if (pool->in_use_count != 0) {
        FAIL("in_use_count should be 0 after releasing all");
        event_buffer_pool_destroy(pool);
        return;
    }
    
    event_buffer_pool_destroy(pool);
    PASS();
}

int main(void) {
    printf("=== Event Buffer Pool Unit Tests ===\n\n");
    
    test_create_destroy();
    test_acquire_release_single();
    test_acquire_multiple();
    test_pool_exhaustion();
    test_event_cleared_on_acquire();
    test_default_capacity();
    test_large_pool();
    
    printf("\n=== Test Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}
