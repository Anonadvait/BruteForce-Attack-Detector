#ifndef DETECTOR_H
#define DETECTOR_H

#include "database.h"
#include <stdbool.h>

#define MAX_TRACKED_IPS 256
#define BRUTE_FORCE_THRESHOLD 3

typedef struct {
    char ip_address[MAX_IP_LEN];
    int consecutive_failures;
    int total_failures;
    int total_attempts;
    bool is_suspicious;          /* Active suspicious status based on threshold */
    bool alert_reported;         /* True if alert already reported for this event */
    char first_flagged_time[MAX_TIME_LEN];
    char last_attempt_time[MAX_TIME_LEN];
} IpRecord;

typedef struct {
    IpRecord records[MAX_TRACKED_IPS];
    int count;
    int total_attempts;
    int total_successes;
    int total_failures;
    int suspicious_ips_count;
} Detector;

void initDetector(Detector *det);
IpRecord* detector_get_or_create_ip(Detector *det, const char *ip);
bool detector_process_attempt(Detector *det, const LoginAttempt *attempt, char *alert_buffer, size_t buffer_size);
void detector_rebuild_from_records(Detector *det, const LoginAttempt records[], int record_count);
void detector_print_summary(const Detector *det);

#endif /* DETECTOR_H */
