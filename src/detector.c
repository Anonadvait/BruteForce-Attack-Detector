#include "detector.h"
#include <stdio.h>
#include <string.h>

static void safe_copy(char *dest, const char *src, size_t dest_size) {
    if (!dest || dest_size == 0) return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    size_t i = 0;
    while (i + 1 < dest_size && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

void initDetector(Detector *det) {
    if (!det) return;
    det->count = 0;
    det->total_attempts = 0;
    det->total_successes = 0;
    det->total_failures = 0;
    det->suspicious_ips_count = 0;
    memset(det->records, 0, sizeof(det->records));
}

IpRecord* detector_get_or_create_ip(Detector *det, const char *ip) {
    if (!det || !ip || strlen(ip) == 0) return NULL;

    /* Search existing IP */
    for (int i = 0; i < det->count; ++i) {
        if (strncmp(det->records[i].ip_address, ip, MAX_IP_LEN) == 0) {
            return &det->records[i];
        }
    }

    /* Create new entry if capacity allows */
    if (det->count < MAX_TRACKED_IPS) {
        IpRecord *rec = &det->records[det->count++];
        memset(rec, 0, sizeof(IpRecord));
        safe_copy(rec->ip_address, ip, sizeof(rec->ip_address));
        return rec;
    }

    fprintf(stderr, "[DETECTOR WARNING] Maximum tracked IP limit reached (%d).\n", MAX_TRACKED_IPS);
    return NULL;
}

bool detector_process_attempt(Detector *det, const LoginAttempt *attempt, char *alert_buffer, size_t buffer_size) {
    if (!det || !attempt) return false;

    if (alert_buffer && buffer_size > 0) {
        alert_buffer[0] = '\0';
    }

    IpRecord *rec = detector_get_or_create_ip(det, attempt->ip_address);
    if (!rec) return false;

    det->total_attempts++;
    rec->total_attempts++;
    safe_copy(rec->last_attempt_time, attempt->timestamp, sizeof(rec->last_attempt_time));

    if (attempt->status == STATUS_FAILED) {
        det->total_failures++;
        rec->total_failures++;
        rec->consecutive_failures++;

        /* Check brute force threshold (3 consecutive failed attempts) */
        if (rec->consecutive_failures >= BRUTE_FORCE_THRESHOLD) {
            bool is_new_flag = !rec->is_suspicious;
            if (is_new_flag) {
                rec->is_suspicious = true;
                det->suspicious_ips_count++;
                safe_copy(rec->first_flagged_time, attempt->timestamp, sizeof(rec->first_flagged_time));
            }

            /* Only trigger an alert if not already reported for this ongoing streak */
            if (!rec->alert_reported) {
                rec->alert_reported = true;
                if (alert_buffer && buffer_size > 0) {
                    snprintf(alert_buffer, buffer_size,
                             "ALERT: Brute-force pattern detected! IP %s reached %d consecutive failed login attempts.",
                             rec->ip_address, rec->consecutive_failures);
                }
                return true; /* New alert generated */
            }
        }
    } else if (attempt->status == STATUS_SUCCESS) {
        det->total_successes++;

        /* A successful login resets the consecutive failure counter for that IP */
        rec->consecutive_failures = 0;
        rec->alert_reported = false;

        if (rec->is_suspicious) {
            rec->is_suspicious = false;
            if (det->suspicious_ips_count > 0) {
                det->suspicious_ips_count--;
            }
        }
    }

    return false;
}

void detector_rebuild_from_records(Detector *det, const LoginAttempt records[], int record_count) {
    if (!det) return;
    initDetector(det);

    char dummy_alert[256];
    for (int i = 0; i < record_count; ++i) {
        detector_process_attempt(det, &records[i], dummy_alert, sizeof(dummy_alert));
    }
}

void detector_print_summary(const Detector *det) {
    if (!det) return;

    printf("\n=== BRUTE-FORCE DETECTOR SUMMARY ===\n");
    printf("  Total Attempts   : %d\n", det->total_attempts);
    printf("  Successful Logins: %d\n", det->total_successes);
    printf("  Failed Logins    : %d\n", det->total_failures);
    printf("  Suspicious IPs   : %d\n", det->suspicious_ips_count);
    printf("  Tracked IP Count : %d\n", det->count);
    printf("------------------------------------\n");

    if (det->count > 0) {
        printf("  %-16s | %-12s | %-10s | %-8s | %s\n",
               "IP Address", "Consec Fail", "Total Fail", "Total", "Status");
        printf("  -----------------+--------------+------------+----------+-----------\n");
        for (int i = 0; i < det->count; ++i) {
            const IpRecord *r = &det->records[i];
            printf("  %-16s | %-12d | %-10d | %-8d | %s\n",
                   r->ip_address,
                   r->consecutive_failures,
                   r->total_failures,
                   r->total_attempts,
                   r->is_suspicious ? "[SUSPICIOUS]" : "Normal");
        }
    }
    printf("====================================\n\n");
}
