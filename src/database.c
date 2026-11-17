#include "database.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

static char g_db_path[512] = "database/login_database.txt";

/* Predefined demonstration credentials (strictly academic demo) */
typedef struct {
    const char *username;
    const char *password;
} DemoCredential;

static const DemoCredential DEMO_USERS[] = {
    {"admin",   "cyber2026!"},
    {"advait",  "matrix99"},
    {"student", "dsa123"},
    {"guest",   "hunter2"}
};
static const int DEMO_USERS_COUNT = sizeof(DEMO_USERS) / sizeof(DEMO_USERS[0]);

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

void db_set_path(const char *path) {
    if (path && strlen(path) > 0) {
        safe_copy(g_db_path, path, sizeof(g_db_path));
    }
}

const char* db_get_path(void) {
    return g_db_path;
}

static void ensure_parent_directory(const char *filepath) {
    char temp[512];
    safe_copy(temp, filepath, sizeof(temp));

    char *last_slash = strrchr(temp, '/');
    char *last_backslash = strrchr(temp, '\\');
    char *separator = last_slash > last_backslash ? last_slash : last_backslash;

    if (separator) {
        *separator = '\0';
#if defined(_WIN32) || defined(_WIN64)
        _mkdir(temp);
#else
        mkdir(temp, 0755);
#endif
    }
}

bool db_ensure_file_exists(void) {
    ensure_parent_directory(g_db_path);

    FILE *fp = fopen(g_db_path, "r");
    if (fp) {
        fclose(fp);
        return true;
    }

    /* File doesn't exist, create it */
    fp = fopen(g_db_path, "w");
    if (!fp) {
        return false;
    }
    fclose(fp);
    return true;
}

void db_get_current_timestamp(char *buffer, size_t buf_size) {
    time_t rawtime;
    struct tm *info;
    time(&rawtime);
    info = localtime(&rawtime);
    if (info) {
        strftime(buffer, buf_size, "%Y-%m-%d %H:%M:%S", info);
    } else {
        snprintf(buffer, buf_size, "1970-01-01 00:00:00");
    }
}

bool db_append_record(const LoginAttempt *attempt) {
    if (!attempt) return false;
    ensure_parent_directory(g_db_path);

    FILE *fp = fopen(g_db_path, "a");
    if (!fp) return false;

    /*
     * Persistent Database - TXT File Format:
     * Username: <name>
     * IP Address: <ip>
     * Status: Success / Failed
     * Timestamp: YYYY-MM-DD HH:MM:SS
     * IP Source: Automatic / Manual
     * --------------------------------
     * NOTE: Passwords are NEVER written to the file for security.
     */
    fprintf(fp, "Username: %s\n", attempt->username);
    fprintf(fp, "IP Address: %s\n", attempt->ip_address);
    fprintf(fp, "Status: %s\n", (attempt->status == STATUS_SUCCESS) ? "Success" : "Failed");
    fprintf(fp, "Timestamp: %s\n", attempt->timestamp);
    fprintf(fp, "IP Source: %s\n", (attempt->ip_source == SOURCE_AUTOMATIC) ? "Automatic" : "Manual");
    fprintf(fp, "--------------------------------\n");

    fclose(fp);
    return true;
}

int db_load_records(LoginAttempt records[], int max_records) {
    if (!records || max_records <= 0) return 0;
    ensure_parent_directory(g_db_path);

    FILE *fp = fopen(g_db_path, "r");
    if (!fp) {
        /* File doesn't exist yet, return 0 */
        return 0;
    }

    char line[256];
    int count = 0;
    LoginAttempt current;
    memset(&current, 0, sizeof(LoginAttempt));
    current.id = 1;

    while (fgets(line, sizeof(line), fp) && count < max_records) {
        /* Remove trailing newline or carriage return */
        line[strcspn(line, "\r\n")] = '\0';

        if (strncmp(line, "Username: ", 10) == 0) {
            safe_copy(current.username, line + 10, sizeof(current.username));
        } else if (strncmp(line, "IP Address: ", 12) == 0) {
            safe_copy(current.ip_address, line + 12, sizeof(current.ip_address));
        } else if (strncmp(line, "Status: ", 8) == 0) {
            if (strcmp(line + 8, "Success") == 0) {
                current.status = STATUS_SUCCESS;
            } else {
                current.status = STATUS_FAILED;
            }
        } else if (strncmp(line, "Timestamp: ", 11) == 0) {
            safe_copy(current.timestamp, line + 11, sizeof(current.timestamp));
        } else if (strncmp(line, "IP Source: ", 11) == 0) {
            if (strcmp(line + 11, "Manual") == 0) {
                current.ip_source = SOURCE_MANUAL;
            } else {
                current.ip_source = SOURCE_AUTOMATIC;
            }
        } else if (strncmp(line, "--------------------------------", 32) == 0) {
            current.id = count + 1;
            records[count] = current;
            count++;
            memset(&current, 0, sizeof(LoginAttempt));
        }
    }

    fclose(fp);
    return count;
}

bool auth_verify_credentials(const char *username, const char *password) {
    if (!username || !password) return false;

    for (int i = 0; i < DEMO_USERS_COUNT; ++i) {
        if (strcmp(username, DEMO_USERS[i].username) == 0 &&
            strcmp(password, DEMO_USERS[i].password) == 0) {
            return true;
        }
    }
    return false;
}
