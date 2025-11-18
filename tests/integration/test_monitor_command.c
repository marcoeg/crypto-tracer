// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_monitor_command.c - Integration test for monitor command
 * Tests the monitor command functionality
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>

#define TEST_DURATION 2  /* Run monitor for 2 seconds */

/**
 * Test 1: Monitor command with duration
 */
int test_monitor_with_duration(void) {
    pid_t pid;
    int status;
    
    printf("Test 1: Monitor with duration...\n");
    
    pid = fork();
    if (pid == 0) {
        /* Child process - run monitor command */
        execl("./build/crypto-tracer", "crypto-tracer", "monitor", 
              "--duration", "2", "--quiet", NULL);
        perror("execl failed");
        exit(1);
    } else if (pid > 0) {
        /* Parent process - wait for child */
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("  ✓ Monitor with duration completed successfully\n");
            return 0;
        } else {
            printf("  ✗ Monitor with duration failed (exit code: %d)\n", 
                   WEXITSTATUS(status));
            return 1;
        }
    } else {
        perror("fork failed");
        return 1;
    }
}

/**
 * Test 2: Monitor command with SIGINT
 */
int test_monitor_with_sigint(void) {
    pid_t pid;
    int status;
    
    printf("Test 2: Monitor with SIGINT...\n");
    
    pid = fork();
    if (pid == 0) {
        /* Child process - run monitor command */
        execl("./build/crypto-tracer", "crypto-tracer", "monitor", 
              "--quiet", NULL);
        perror("execl failed");
        exit(1);
    } else if (pid > 0) {
        /* Parent process - wait a bit then send SIGINT */
        sleep(1);
        kill(pid, SIGINT);
        
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("  ✓ Monitor with SIGINT completed successfully\n");
            return 0;
        } else {
            printf("  ✗ Monitor with SIGINT failed (exit code: %d)\n", 
                   WEXITSTATUS(status));
            return 1;
        }
    } else {
        perror("fork failed");
        return 1;
    }
}

/**
 * Test 3: Monitor command with output file
 */
int test_monitor_with_output_file(void) {
    pid_t pid;
    int status;
    FILE *fp;
    char line[256];
    int has_output = 0;
    
    printf("Test 3: Monitor with output file...\n");
    
    /* Remove old test file if exists */
    unlink("/tmp/crypto-tracer-test.json");
    
    pid = fork();
    if (pid == 0) {
        /* Child process - run monitor command */
        execl("./build/crypto-tracer", "crypto-tracer", "monitor", 
              "--duration", "2", "--output", "/tmp/crypto-tracer-test.json",
              "--quiet", NULL);
        perror("execl failed");
        exit(1);
    } else if (pid > 0) {
        /* Parent process - wait for child */
        waitpid(pid, &status, 0);
        
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            printf("  ✗ Monitor command failed (exit code: %d)\n", 
                   WEXITSTATUS(status));
            return 1;
        }
        
        /* Check if output file was created */
        fp = fopen("/tmp/crypto-tracer-test.json", "r");
        if (!fp) {
            printf("  ✗ Output file not created\n");
            return 1;
        }
        
        /* Check if file has content (may be empty if no events) */
        if (fgets(line, sizeof(line), fp) != NULL) {
            has_output = 1;
        }
        fclose(fp);
        
        /* Clean up */
        unlink("/tmp/crypto-tracer-test.json");
        
        printf("  ✓ Monitor with output file completed successfully\n");
        if (has_output) {
            printf("    (Output file contained events)\n");
        } else {
            printf("    (Output file was empty - no events captured)\n");
        }
        return 0;
    } else {
        perror("fork failed");
        return 1;
    }
}

/**
 * Test 4: Monitor command with filters
 */
int test_monitor_with_filters(void) {
    pid_t pid;
    int status;
    
    printf("Test 4: Monitor with filters...\n");
    
    pid = fork();
    if (pid == 0) {
        /* Child process - run monitor command with filters */
        execl("./build/crypto-tracer", "crypto-tracer", "monitor", 
              "--duration", "2", "--library", "libssl", 
              "--quiet", NULL);
        perror("execl failed");
        exit(1);
    } else if (pid > 0) {
        /* Parent process - wait for child */
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("  ✓ Monitor with filters completed successfully\n");
            return 0;
        } else {
            printf("  ✗ Monitor with filters failed (exit code: %d)\n", 
                   WEXITSTATUS(status));
            return 1;
        }
    } else {
        perror("fork failed");
        return 1;
    }
}

int main(void) {
    int failures = 0;
    
    printf("=== Monitor Command Integration Tests ===\n\n");
    
    /* Check if running as root or with capabilities */
    if (geteuid() != 0) {
        printf("Warning: Not running as root. Tests may fail due to insufficient privileges.\n");
        printf("Run with: sudo ./test_monitor_command\n\n");
    }
    
    failures += test_monitor_with_duration();
    failures += test_monitor_with_sigint();
    failures += test_monitor_with_output_file();
    failures += test_monitor_with_filters();
    
    printf("\n=== Test Summary ===\n");
    if (failures == 0) {
        printf("All tests passed! ✓\n");
        return 0;
    } else {
        printf("%d test(s) failed ✗\n", failures);
        return 1;
    }
}
