#ifndef DATABASE_H
#define DATABASE_H

#include <stdbool.h>
#include <stddef.h>

#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64
#define MAX_IP_LEN       46
#define MAX_TIME_LEN     32
#define MAX_SOURCE_LEN   16

typedef enum {
    STATUS_FAILED = 0,
    STATUS_SUCCESS = 1
} LoginStatus;

typedef enum {
    SOURCE_AUTOMATIC = 0,
    SOURCE_MANUAL = 1
} IpSource;

typedef struct {
    int id;                                /* Sequence / attempt ID */
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];       /* Kept in memory only; NEVER saved to disk */
    char ip_address[MAX_IP_LEN];
    LoginStatus status;
    char timestamp[MAX_TIME_LEN];
    IpSource ip_source;
} LoginAttempt;

/*
 * Database file management
 */
void db_set_path(const char *path);
const char* db_get_path(void);
bool db_ensure_file_exists(void);
bool db_append_record(const LoginAttempt *attempt);
int  db_load_records(LoginAttempt records[], int max_records);
void db_get_current_timestamp(char *buffer, size_t buf_size);

/* Predefined demo credentials check (pure C verification) */
bool auth_verify_credentials(const char *username, const char *password);

#endif /* DATABASE_H */
