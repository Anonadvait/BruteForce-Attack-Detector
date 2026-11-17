#include "database.h"
#include "queue.h"
#include "stack.h"
#include "detector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RUNTIME_STATE_FILE "database/.runtime_state.dat"
#define MAX_HISTORY_DISPLAY 200

typedef struct {
    Queue queue;
    Stack stack;
    Detector detector;
} AppState;

static AppState g_app;

/* Save / restore transient queue state between CLI calls if run as separate processes */
static void save_runtime_state(void) {
    db_ensure_file_exists();
    FILE *fp = fopen(RUNTIME_STATE_FILE, "wb");
    if (!fp) return;
    fwrite(&g_app.queue, sizeof(Queue), 1, fp);
    fclose(fp);
}

static void load_runtime_state(void) {
    FILE *fp = fopen(RUNTIME_STATE_FILE, "rb");
    if (!fp) return;
    fread(&g_app.queue, sizeof(Queue), 1, fp);
    fclose(fp);
}

/* Initialize application state from persistent TXT database */
static void app_init(const char *db_path) {
    if (db_path && strlen(db_path) > 0) {
        db_set_path(db_path);
    }
    db_ensure_file_exists();

    initQueue(&g_app.queue);
    initStack(&g_app.stack);
    initDetector(&g_app.detector);

    /* Load history from login_database.txt */
    static LoginAttempt history[MAX_HISTORY_DISPLAY];
    int loaded = db_load_records(history, MAX_HISTORY_DISPLAY);

    /* Rebuild detector state and populate Stack with recent history */
    detector_rebuild_from_records(&g_app.detector, history, loaded);

    for (int i = 0; i < loaded; ++i) {
        push(&g_app.stack, history[i]);
    }

    /* Restore any pending queue elements from runtime storage */
    load_runtime_state();
}

/* JSON Output Helpers for Python Integration */
static void escape_json_string(const char *input, char *output, size_t out_size) {
    if (!input || !output || out_size == 0) return;
    size_t j = 0;
    for (size_t i = 0; input[i] != '\0' && j + 2 < out_size; ++i) {
        if (input[i] == '\"' || input[i] == '\\') {
            output[j++] = '\\';
            output[j++] = input[i];
        } else if (input[i] == '\n') {
            output[j++] = '\\';
            output[j++] = 'n';
        } else if (input[i] == '\r') {
            /* skip */
        } else {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

static void print_state_json(const char *last_action, const char *alert_msg, const LoginAttempt *last_processed) {
    printf("{\n");
    printf("  \"status\": \"success\",\n");
    printf("  \"last_action\": \"%s\",\n", last_action ? last_action : "none");

    char esc_alert[512] = "";
    if (alert_msg && strlen(alert_msg) > 0) {
        escape_json_string(alert_msg, esc_alert, sizeof(esc_alert));
    }
    printf("  \"alert\": \"%s\",\n", esc_alert);

    /* Stats */
    printf("  \"stats\": {\n");
    printf("    \"total_attempts\": %d,\n", g_app.detector.total_attempts);
    printf("    \"successful_logins\": %d,\n", g_app.detector.total_successes);
    printf("    \"failed_logins\": %d,\n", g_app.detector.total_failures);
    printf("    \"suspicious_ips_count\": %d,\n", g_app.detector.suspicious_ips_count);
    printf("    \"pending_queue_count\": %d,\n", g_app.queue.count);
    printf("    \"stack_history_count\": %d\n", g_app.stack.top + 1);
    printf("  },\n");

    /* Last Processed */
    printf("  \"last_processed\": ");
    if (last_processed) {
        printf("{\n");
        printf("    \"username\": \"%s\",\n", last_processed->username);
        printf("    \"ip_address\": \"%s\",\n", last_processed->ip_address);
        printf("    \"status\": \"%s\",\n", (last_processed->status == STATUS_SUCCESS) ? "Success" : "Failed");
        printf("    \"timestamp\": \"%s\",\n", last_processed->timestamp);
        printf("    \"ip_source\": \"%s\"\n", (last_processed->ip_source == SOURCE_AUTOMATIC) ? "Automatic" : "Manual");
        printf("  },\n");
    } else {
        printf("null,\n");
    }

    /* Queue Items (front to rear) */
    printf("  \"queue\": [\n");
    int q_idx = g_app.queue.front;
    for (int i = 0; i < g_app.queue.count; ++i) {
        const LoginAttempt *item = &g_app.queue.items[q_idx];
        printf("    {\n");
        printf("      \"index\": %d,\n", i);
        printf("      \"username\": \"%s\",\n", item->username);
        printf("      \"ip_address\": \"%s\",\n", item->ip_address);
        printf("      \"ip_source\": \"%s\"\n", (item->ip_source == SOURCE_AUTOMATIC) ? "Automatic" : "Manual");
        printf("    }%s\n", (i < g_app.queue.count - 1) ? "," : "");
        q_idx = (q_idx + 1) % MAX_QUEUE;
    }
    printf("  ],\n");

    /* Stack Items (top to bottom) */
    printf("  \"stack\": [\n");
    for (int i = g_app.stack.top; i >= 0; --i) {
        const LoginAttempt *item = &g_app.stack.items[i];
        printf("    {\n");
        printf("      \"index\": %d,\n", i);
        printf("      \"username\": \"%s\",\n", item->username);
        printf("      \"ip_address\": \"%s\",\n", item->ip_address);
        printf("      \"status\": \"%s\",\n", (item->status == STATUS_SUCCESS) ? "Success" : "Failed");
        printf("      \"timestamp\": \"%s\",\n", item->timestamp);
        printf("      \"ip_source\": \"%s\"\n", (item->ip_source == SOURCE_AUTOMATIC) ? "Automatic" : "Manual");
        printf("    }%s\n", (i > 0) ? "," : "");
    }
    printf("  ],\n");

    /* Suspicious IPs */
    printf("  \"suspicious_ips\": [\n");
    int susp_printed = 0;
    for (int i = 0; i < g_app.detector.count; ++i) {
        const IpRecord *r = &g_app.detector.records[i];
        if (r->is_suspicious || r->consecutive_failures > 0) {
            if (susp_printed > 0) printf(",\n");
            printf("    {\n");
            printf("      \"ip_address\": \"%s\",\n", r->ip_address);
            printf("      \"consecutive_failures\": %d,\n", r->consecutive_failures);
            printf("      \"total_failures\": %d,\n", r->total_failures);
            printf("      \"total_attempts\": %d,\n", r->total_attempts);
            printf("      \"is_suspicious\": %s,\n", r->is_suspicious ? "true" : "false");
            printf("      \"first_flagged\": \"%s\",\n", r->first_flagged_time);
            printf("      \"last_attempt\": \"%s\"\n", r->last_attempt_time);
            printf("    }");
            susp_printed++;
        }
    }
    printf("\n  ]\n");
    printf("}\n");
}

/* Enqueue a new incoming attempt */
static bool do_enqueue(const char *username, const char *password, const char *ip, const char *source_str, char *err_msg, size_t err_size) {
    if (isQueueFull(&g_app.queue)) {
        if (err_msg) snprintf(err_msg, err_size, "Queue Overflow! Maximum queue capacity (%d) reached.", MAX_QUEUE);
        return false;
    }

    LoginAttempt attempt;
    memset(&attempt, 0, sizeof(LoginAttempt));
    strncpy(attempt.username, username, sizeof(attempt.username) - 1);
    strncpy(attempt.password, password, sizeof(attempt.password) - 1);
    strncpy(attempt.ip_address, ip, sizeof(attempt.ip_address) - 1);

    if (source_str && strcmp(source_str, "Manual") == 0) {
        attempt.ip_source = SOURCE_MANUAL;
    } else {
        attempt.ip_source = SOURCE_AUTOMATIC;
    }

    bool ok = enqueue(&g_app.queue, attempt);
    if (ok) {
        save_runtime_state();
    }
    return ok;
}

/* Dequeue and process next attempt through detector, database, and stack */
static bool do_process_next(char *alert_msg, size_t alert_size, LoginAttempt *out_attempt) {
    if (isQueueEmpty(&g_app.queue)) {
        if (alert_msg) snprintf(alert_msg, alert_size, "Queue Underflow! No pending login attempts to process.");
        return false;
    }

    LoginAttempt attempt;
    if (!dequeue(&g_app.queue, &attempt)) {
        return false;
    }

    /* 1. Verify credentials in pure C */
    bool auth_ok = auth_verify_credentials(attempt.username, attempt.password);
    attempt.status = auth_ok ? STATUS_SUCCESS : STATUS_FAILED;

    /* 2. Stamp current time */
    db_get_current_timestamp(attempt.timestamp, sizeof(attempt.timestamp));

    /* 3. Run through Brute-Force Detector */
    detector_process_attempt(&g_app.detector, &attempt, alert_msg, alert_size);

    /* 4. Append to Persistent TXT Database (password is NEVER written) */
    db_append_record(&attempt);

    /* 5. Push to Recent Activity Stack */
    push(&g_app.stack, attempt);

    /* 6. Save runtime queue state */
    save_runtime_state();

    if (out_attempt) {
        *out_attempt = attempt;
    }
    return true;
}

/* Direct Login: Enqueue immediately, then Dequeue & Process */
static bool do_direct_login(const char *username, const char *password, const char *ip, const char *source_str,
                            char *alert_msg, size_t alert_size, LoginAttempt *out_attempt) {
    char err[256] = "";
    if (!do_enqueue(username, password, ip, source_str, err, sizeof(err))) {
        if (alert_msg) snprintf(alert_msg, alert_size, "%s", err);
        return false;
    }
    return do_process_next(alert_msg, alert_size, out_attempt);
}

/* Record an attempt with pre-verified status (e.g. from Python PBKDF2 authentication) */
static bool do_record_attempt(const char *username, int status_val, const char *ip, const char *source_str,
                              char *alert_msg, size_t alert_size, LoginAttempt *out_attempt) {
    if (isQueueFull(&g_app.queue)) {
        if (alert_msg) snprintf(alert_msg, alert_size, "Queue Overflow! Maximum queue capacity (%d) reached.", MAX_QUEUE);
        return false;
    }

    LoginAttempt attempt;
    memset(&attempt, 0, sizeof(LoginAttempt));
    strncpy(attempt.username, username, sizeof(attempt.username) - 1);
    strncpy(attempt.ip_address, ip, sizeof(attempt.ip_address) - 1);
    attempt.status = (status_val == 1) ? STATUS_SUCCESS : STATUS_FAILED;

    if (source_str && (strstr(source_str, "Manual") || strstr(source_str, "Simulated"))) {
        attempt.ip_source = SOURCE_MANUAL;
    } else {
        attempt.ip_source = SOURCE_AUTOMATIC;
    }

    /* 1. Enter Queue (FIFO) */
    enqueue(&g_app.queue, attempt);

    /* 2. Dequeue immediately in FIFO order */
    dequeue(&g_app.queue, &attempt);

    /* 3. Stamp current time */
    db_get_current_timestamp(attempt.timestamp, sizeof(attempt.timestamp));

    /* 4. Run through Brute-Force Detector */
    detector_process_attempt(&g_app.detector, &attempt, alert_msg, alert_size);

    /* 5. Append to Persistent TXT Database (password is NEVER written) */
    db_append_record(&attempt);

    /* 6. Push to Recent Activity Stack (LIFO) */
    push(&g_app.stack, attempt);

    /* 7. Save runtime queue state */
    save_runtime_state();

    if (out_attempt) {
        *out_attempt = attempt;
    }
    return true;
}

/* Automated scenario test runner for academic verification & viva */
static int run_test_suite(void) {
    printf("========================================================\n");
    printf("  RUNNING BRUTEFORCE ATTACK DETECTOR TEST SUITE\n");
    printf("========================================================\n\n");

    /* Use a temporary test database */
    db_set_path("database/test_login_database.txt");
    remove("database/test_login_database.txt");
    remove("database/.runtime_state.dat");

    AppState test_state;
    initQueue(&test_state.queue);
    initStack(&test_state.stack);
    initDetector(&test_state.detector);

    int passed = 0;
    int total_tests = 10;
    char alert[256] = "";

    /* Test 1: 3 failed attempts from same IP trigger an alert */
    {
        printf("[Test 1] 3 failed login attempts from same IP trigger alert... ");
        LoginAttempt att = {.username = "attacker", .ip_address = "10.0.0.1", .status = STATUS_FAILED};
        strcpy(att.timestamp, "2026-11-17 10:00:01");
        detector_process_attempt(&test_state.detector, &att, alert, sizeof(alert));

        att.status = STATUS_FAILED;
        strcpy(att.timestamp, "2026-11-17 10:00:02");
        detector_process_attempt(&test_state.detector, &att, alert, sizeof(alert));

        att.status = STATUS_FAILED;
        strcpy(att.timestamp, "2026-11-17 10:00:03");
        bool alert_fired = detector_process_attempt(&test_state.detector, &att, alert, sizeof(alert));

        IpRecord *rec = detector_get_or_create_ip(&test_state.detector, "10.0.0.1");
        if (alert_fired && rec && rec->is_suspicious && rec->consecutive_failures == 3) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL (alert_fired=%d, consecutive=%d)\n", alert_fired, rec ? rec->consecutive_failures : -1);
        }
    }

    /* Test 2: 2 failed attempts followed by 1 successful attempt do not trigger alert */
    {
        printf("[Test 2] 2 failed attempts followed by 1 successful attempt... ");
        initDetector(&test_state.detector);
        LoginAttempt att = {.username = "user1", .ip_address = "10.0.0.2", .status = STATUS_FAILED};
        strcpy(att.timestamp, "2026-11-17 10:01:00");
        detector_process_attempt(&test_state.detector, &att, alert, sizeof(alert));

        strcpy(att.timestamp, "2026-11-17 10:01:01");
        detector_process_attempt(&test_state.detector, &att, alert, sizeof(alert));

        att.status = STATUS_SUCCESS;
        strcpy(att.timestamp, "2026-11-17 10:01:02");
        bool alert_fired = detector_process_attempt(&test_state.detector, &att, alert, sizeof(alert));

        IpRecord *rec = detector_get_or_create_ip(&test_state.detector, "10.0.0.2");
        if (!alert_fired && rec && rec->consecutive_failures == 0 && !rec->is_suspicious) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL (alert_fired=%d, consecutive=%d)\n", alert_fired, rec ? rec->consecutive_failures : -1);
        }
    }

    /* Test 3: Failed attempts from different IPs are tracked independently */
    {
        printf("[Test 3] Failed attempts from different IPs tracked independently... ");
        initDetector(&test_state.detector);
        LoginAttempt a1 = {.username = "userA", .ip_address = "192.168.1.50", .status = STATUS_FAILED};
        LoginAttempt a2 = {.username = "userB", .ip_address = "192.168.1.60", .status = STATUS_FAILED};

        detector_process_attempt(&test_state.detector, &a1, alert, sizeof(alert));
        detector_process_attempt(&test_state.detector, &a1, alert, sizeof(alert));
        detector_process_attempt(&test_state.detector, &a2, alert, sizeof(alert));

        IpRecord *r1 = detector_get_or_create_ip(&test_state.detector, "192.168.1.50");
        IpRecord *r2 = detector_get_or_create_ip(&test_state.detector, "192.168.1.60");

        if (r1 && r2 && r1->consecutive_failures == 2 && r2->consecutive_failures == 1) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL (IP1 consec=%d, IP2 consec=%d)\n", r1 ? r1->consecutive_failures : -1, r2 ? r2->consecutive_failures : -1);
        }
    }

    /* Test 4: Stack correctly maintains recent login history (LIFO) */
    {
        printf("[Test 4] Stack maintains recent login history (LIFO)... ");
        Stack s;
        initStack(&s);
        LoginAttempt item1 = {.username = "first"};
        LoginAttempt item2 = {.username = "second"};
        push(&s, item1);
        push(&s, item2);

        LoginAttempt peeked, popped;
        peek(&s, &peeked);
        pop(&s, &popped);

        if (strcmp(peeked.username, "second") == 0 && strcmp(popped.username, "second") == 0) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL\n");
        }
    }

    /* Test 5: Queue processes attempts in FIFO order */
    {
        printf("[Test 5] Queue processes attempts in FIFO order... ");
        Queue q;
        initQueue(&q);
        LoginAttempt itemA = {.username = "alpha"};
        LoginAttempt itemB = {.username = "beta"};
        enqueue(&q, itemA);
        enqueue(&q, itemB);

        LoginAttempt dequeued;
        dequeue(&q, &dequeued);

        if (strcmp(dequeued.username, "alpha") == 0) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL\n");
        }
    }

    /* Test 6: Stack overflow and underflow handled */
    {
        printf("[Test 6] Stack overflow and underflow handled... ");
        Stack s;
        initStack(&s);
        LoginAttempt dummy;
        bool underflow_handled = !pop(&s, &dummy);

        for (int i = 0; i < MAX_STACK; ++i) {
            push(&s, dummy);
        }
        bool overflow_handled = !push(&s, dummy);

        if (underflow_handled && overflow_handled) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL (underflow=%d, overflow=%d)\n", underflow_handled, overflow_handled);
        }
    }

    /* Test 7: Queue overflow and underflow handled */
    {
        printf("[Test 7] Queue overflow and underflow handled... ");
        Queue q;
        initQueue(&q);
        LoginAttempt dummy;
        bool underflow_handled = !dequeue(&q, &dummy);

        for (int i = 0; i < MAX_QUEUE; ++i) {
            enqueue(&q, dummy);
        }
        bool overflow_handled = !enqueue(&q, dummy);

        if (underflow_handled && overflow_handled) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL (underflow=%d, overflow=%d)\n", underflow_handled, overflow_handled);
        }
    }

    /* Test 8: Login records are preserved after closing and reopening */
    {
        printf("[Test 8] Login records preserved after closing and reopening... ");
        db_set_path("database/test_login_database.txt");
        LoginAttempt sample = {
            .username = "preserve_user",
            .ip_address = "172.16.0.4",
            .status = STATUS_SUCCESS,
            .timestamp = "2026-11-17 12:00:00",
            .ip_source = SOURCE_AUTOMATIC
        };
        db_append_record(&sample);

        LoginAttempt loaded[10];
        int count = db_load_records(loaded, 10);
        if (count > 0 && strcmp(loaded[count - 1].username, "preserve_user") == 0) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL (loaded count=%d)\n", count);
        }
    }

    /* Test 9: Missing database files created automatically */
    {
        printf("[Test 9] Missing database files created automatically... ");
        db_set_path("database/auto_created_test.txt");
        remove("database/auto_created_test.txt");
        bool created = db_ensure_file_exists();
        FILE *fp = fopen("database/auto_created_test.txt", "r");
        if (created && fp) {
            fclose(fp);
            remove("database/auto_created_test.txt");
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL\n");
        }
    }

    /* Test 10: Passwords are never stored in the database file */
    {
        printf("[Test 10] Passwords are never stored in database file... ");
        db_set_path("database/test_password_check.txt");
        remove("database/test_password_check.txt");

        LoginAttempt secret = {
            .username = "secret_agent",
            .password = "TopSecretPassword123!",
            .ip_address = "127.0.0.1",
            .status = STATUS_SUCCESS,
            .timestamp = "2026-11-17 12:05:00",
            .ip_source = SOURCE_AUTOMATIC
        };
        db_append_record(&secret);

        FILE *fp = fopen("database/test_password_check.txt", "r");
        char buffer[1024] = {0};
        if (fp) {
            fread(buffer, 1, sizeof(buffer) - 1, fp);
            fclose(fp);
        }
        remove("database/test_password_check.txt");

        if (strstr(buffer, "TopSecretPassword123!") == NULL && strstr(buffer, "secret_agent") != NULL) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL (Password leaked into TXT file!)\n");
        }
    }

    /* Clean up temporary test database */
    remove("database/test_login_database.txt");

    printf("\n========================================================\n");
    printf("  TEST RESULTS: %d / %d PASSED (%.1f%%)\n", passed, total_tests, (float)passed / total_tests * 100.0f);
    printf("========================================================\n\n");
    return (passed == total_tests) ? 0 : 1;
}

/* Interactive text menu for direct terminal / viva demonstration */
static void run_cli_menu(void) {
    char choice[32];
    char username[64], password[64], ip[46], source[16];

    while (1) {
        printf("\n====================================================\n");
        printf("    BRUTEFORCE ATTACK DETECTOR - C CORE ENGINE\n");
        printf("====================================================\n");
        printf("  [1] Direct Login Attempt (Enqueue -> Process)\n");
        printf("  [2] Enqueue Login Attempt into Queue (FIFO)\n");
        printf("  [3] Dequeue & Process Next Attempt from Queue\n");
        printf("  [4] Display Pending Queue\n");
        printf("  [5] Display Recent Activity Stack (LIFO)\n");
        printf("  [6] Pop Top Element from Stack\n");
        printf("  [7] Peek Top Element of Stack\n");
        printf("  [8] View Brute-Force Detector Summary\n");
        printf("  [9] View Persistent Database File (login_database.txt)\n");
        printf("  [T] Run All 10 Automated Validation Tests\n");
        printf("  [0] Exit\n");
        printf("----------------------------------------------------\n");
        printf("  Enter choice: ");
        if (!fgets(choice, sizeof(choice), stdin)) break;

        char c = choice[0];
        if (c == '0') break;

        if (c == '1' || c == '2') {
            printf("  Username: ");
            if (!fgets(username, sizeof(username), stdin)) continue;
            username[strcspn(username, "\r\n")] = '\0';

            printf("  Password: ");
            if (!fgets(password, sizeof(password), stdin)) continue;
            password[strcspn(password, "\r\n")] = '\0';

            printf("  IP Address (e.g., 192.168.1.100): ");
            if (!fgets(ip, sizeof(ip), stdin)) continue;
            ip[strcspn(ip, "\r\n")] = '\0';

            printf("  IP Source (1 for Automatic, 2 for Manual): ");
            if (!fgets(source, sizeof(source), stdin)) continue;
            const char *src_str = (source[0] == '2') ? "Manual" : "Automatic";

            if (c == '1') {
                char alert[256] = "";
                LoginAttempt processed;
                bool ok = do_direct_login(username, password, ip, src_str, alert, sizeof(alert), &processed);
                if (ok) {
                    printf("\n  [RESULT] Status: %s | User: %s | IP: %s\n",
                           (processed.status == STATUS_SUCCESS) ? "SUCCESS" : "FAILED",
                           processed.username, processed.ip_address);
                    if (strlen(alert) > 0) {
                        printf("  >>> %s <<<\n", alert);
                    }
                } else {
                    printf("\n  [FAILED] %s\n", alert);
                }
            } else {
                char err[256] = "";
                bool ok = do_enqueue(username, password, ip, src_str, err, sizeof(err));
                if (ok) {
                    printf("\n  [QUEUE] Successfully enqueued attempt for '%s' from %s.\n", username, ip);
                } else {
                    printf("\n  [QUEUE ERROR] %s\n", err);
                }
            }
        } else if (c == '3') {
            char alert[256] = "";
            LoginAttempt processed;
            bool ok = do_process_next(alert, sizeof(alert), &processed);
            if (ok) {
                printf("\n  [DEQUEUED & PROCESSED] Status: %s | User: %s | IP: %s\n",
                       (processed.status == STATUS_SUCCESS) ? "SUCCESS" : "FAILED",
                       processed.username, processed.ip_address);
                if (strlen(alert) > 0) {
                    printf("  >>> %s <<<\n", alert);
                }
            } else {
                printf("\n  [QUEUE EMPTY] %s\n", alert);
            }
        } else if (c == '4') {
            displayQueue(&g_app.queue);
        } else if (c == '5') {
            displayStack(&g_app.stack);
        } else if (c == '6') {
            LoginAttempt popped;
            if (pop(&g_app.stack, &popped)) {
                printf("\n  [STACK POP] Removed most recent attempt: User=%s, IP=%s, Status=%s\n",
                       popped.username, popped.ip_address,
                       (popped.status == STATUS_SUCCESS) ? "Success" : "Failed");
            } else {
                printf("\n  [STACK EMPTY] Underflow! Stack is empty.\n");
            }
        } else if (c == '7') {
            LoginAttempt peeked;
            if (peek(&g_app.stack, &peeked)) {
                printf("\n  [STACK PEEK] Top attempt: User=%s, IP=%s, Status=%s, Time=%s\n",
                       peeked.username, peeked.ip_address,
                       (peeked.status == STATUS_SUCCESS) ? "Success" : "Failed",
                       peeked.timestamp);
            } else {
                printf("\n  [STACK EMPTY] Nothing to peek.\n");
            }
        } else if (c == '8') {
            detector_print_summary(&g_app.detector);
        } else if (c == '9') {
            FILE *fp = fopen(db_get_path(), "r");
            if (!fp) {
                printf("\n  [DATABASE] File '%s' not found or empty.\n", db_get_path());
            } else {
                printf("\n--- Contents of %s ---\n", db_get_path());
                char line[256];
                int lines = 0;
                while (fgets(line, sizeof(line), fp)) {
                    printf("%s", line);
                    lines++;
                }
                if (lines == 0) printf("  [Empty file]\n");
                printf("--- End of File (%d lines) ---\n", lines);
                fclose(fp);
            }
        } else if (c == 'T' || c == 't') {
            run_test_suite();
            /* Reinitialize state with main database */
            app_init(NULL);
        }
    }
}

int main(int argc, char *argv[]) {
    /* Initialize application with default database */
    app_init("database/login_database.txt");

    /* Subcommand CLI Mode (used by Python GUI or scripting) */
    if (argc >= 2) {
        const char *cmd = argv[1];

        if (strcmp(cmd, "get-state") == 0) {
            print_state_json("get-state", NULL, NULL);
            return 0;
        }

        if (strcmp(cmd, "enqueue") == 0) {
            if (argc < 5) {
                fprintf(stderr, "Usage: %s enqueue <username> <password> <ip> [source]\n", argv[0]);
                return 1;
            }
            const char *username = argv[2];
            const char *password = argv[3];
            const char *ip = argv[4];
            const char *source = (argc >= 6) ? argv[5] : "Automatic";

            char err[256] = "";
            bool ok = do_enqueue(username, password, ip, source, err, sizeof(err));
            print_state_json("enqueue", ok ? NULL : err, NULL);
            return ok ? 0 : 1;
        }

        if (strcmp(cmd, "process-next") == 0) {
            char alert[256] = "";
            LoginAttempt processed;
            bool ok = do_process_next(alert, sizeof(alert), &processed);
            print_state_json("process-next", (strlen(alert) > 0) ? alert : NULL, ok ? &processed : NULL);
            return ok ? 0 : 1;
        }

        if (strcmp(cmd, "login-direct") == 0) {
            if (argc < 5) {
                fprintf(stderr, "Usage: %s login-direct <username> <password> <ip> [source]\n", argv[0]);
                return 1;
            }
            const char *username = argv[2];
            const char *password = argv[3];
            const char *ip = argv[4];
            const char *source = (argc >= 6) ? argv[5] : "Automatic";

            char alert[256] = "";
            LoginAttempt processed;
            bool ok = do_direct_login(username, password, ip, source, alert, sizeof(alert), &processed);
            print_state_json("login-direct", (strlen(alert) > 0) ? alert : NULL, ok ? &processed : NULL);
            return ok ? 0 : 1;
        }

        if (strcmp(cmd, "record-attempt") == 0) {
            if (argc < 5) {
                fprintf(stderr, "Usage: %s record-attempt <username> <status 0/1> <ip> [source]\n", argv[0]);
                return 1;
            }
            const char *username = argv[2];
            int status_val = atoi(argv[3]);
            const char *ip = argv[4];
            const char *source = (argc >= 6) ? argv[5] : "Automatic";

            char alert[256] = "";
            LoginAttempt processed;
            bool ok = do_record_attempt(username, status_val, ip, source, alert, sizeof(alert), &processed);
            print_state_json("record-attempt", (strlen(alert) > 0) ? alert : NULL, ok ? &processed : NULL);
            return ok ? 0 : 1;
        }

        if (strcmp(cmd, "stack-pop") == 0) {
            LoginAttempt popped;
            bool ok = pop(&g_app.stack, &popped);
            print_state_json("stack-pop", ok ? NULL : "Stack Underflow", ok ? &popped : NULL);
            return ok ? 0 : 1;
        }

        if (strcmp(cmd, "test") == 0) {
            return run_test_suite();
        }

        if (strcmp(cmd, "interactive") == 0) {
            char line[512];
            while (fgets(line, sizeof(line), stdin)) {
                line[strcspn(line, "\r\n")] = '\0';
                if (strlen(line) == 0) continue;

                if (strncmp(line, "STATE", 5) == 0) {
                    print_state_json("state", NULL, NULL);
                } else if (strncmp(line, "ENQUEUE ", 8) == 0) {
                    char u[64], p[64], ip[46], s[16];
                    int parsed = sscanf(line + 8, "%63s %63s %45s %15s", u, p, ip, s);
                    if (parsed >= 3) {
                        char err[256] = "";
                        bool ok = do_enqueue(u, p, ip, (parsed >= 4) ? s : "Automatic", err, sizeof(err));
                        print_state_json("enqueue", ok ? NULL : err, NULL);
                    }
                } else if (strncmp(line, "PROCESS", 7) == 0) {
                    char alert[256] = "";
                    LoginAttempt proc;
                    bool ok = do_process_next(alert, sizeof(alert), &proc);
                    print_state_json("process-next", (strlen(alert) > 0) ? alert : NULL, ok ? &proc : NULL);
                } else if (strncmp(line, "LOGIN ", 6) == 0) {
                    char u[64], p[64], ip[46], s[16];
                    int parsed = sscanf(line + 6, "%63s %63s %45s %15s", u, p, ip, s);
                    if (parsed >= 3) {
                        char alert[256] = "";
                        LoginAttempt proc;
                        bool ok = do_direct_login(u, p, ip, (parsed >= 4) ? s : "Automatic", alert, sizeof(alert), &proc);
                        print_state_json("login-direct", (strlen(alert) > 0) ? alert : NULL, ok ? &proc : NULL);
                    }
                } else if (strncmp(line, "RECORD ", 7) == 0) {
                    char u[64], ip[46], s[16];
                    int st_val = 0;
                    int parsed = sscanf(line + 7, "%63s %d %45s %15s", u, &st_val, ip, s);
                    if (parsed >= 3) {
                        char alert[256] = "";
                        LoginAttempt proc;
                        bool ok = do_record_attempt(u, st_val, ip, (parsed >= 4) ? s : "Automatic", alert, sizeof(alert), &proc);
                        print_state_json("record-attempt", (strlen(alert) > 0) ? alert : NULL, ok ? &proc : NULL);
                    }
                } else if (strncmp(line, "POP", 3) == 0) {
                    LoginAttempt popped;
                    bool ok = pop(&g_app.stack, &popped);
                    print_state_json("stack-pop", ok ? NULL : "Stack Underflow", ok ? &popped : NULL);
                } else if (strncmp(line, "EXIT", 4) == 0 || strncmp(line, "QUIT", 4) == 0) {
                    break;
                }
                fflush(stdout);
            }
            return 0;
        }

        if (strcmp(cmd, "cli") == 0) {
            run_cli_menu();
            return 0;
        }

        fprintf(stderr, "Unknown command: %s\n", cmd);
        return 1;
    }

    /* Default: Launch Cyberpunk Tkinter GUI if available, or print usage */
#if defined(_WIN32) || defined(_WIN64)
    FILE *test_gui = fopen("gui/app.py", "r");
    if (test_gui) {
        fclose(test_gui);
        int ret = system("python gui/app.py");
        if (ret == 0) return 0;
    }
#endif

    printf("====================================================\n");
    printf("  BRUTEFORCE ATTACK DETECTOR - C CORE ENGINE\n");
    printf("====================================================\n");
    printf("  To launch the Cyberpunk GUI, run:\n");
    printf("    run.bat  OR  python gui/app.py\n\n");
    printf("  C Subcommands:\n");
    printf("    ./bruteforce_detector get-state\n");
    printf("    ./bruteforce_detector login-direct <user> <pass> <ip> [source]\n");
    printf("    ./bruteforce_detector enqueue <user> <pass> <ip> [source]\n");
    printf("    ./bruteforce_detector process-next\n");
    printf("    ./bruteforce_detector stack-pop\n");
    printf("    ./bruteforce_detector test\n");
    printf("    ./bruteforce_detector cli\n");
    printf("====================================================\n");
    return 0;
}
