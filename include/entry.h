#ifndef ENTRY_H
#define ENTRY_H

#include "common.h"

// Password entry structure
typedef struct {
    char domain[MAX_DOMAIN_LEN + 1];
    char username[MAX_USERNAME_LEN + 1];
    char password[MAX_PASSWORD_LEN + 1];
    char comment[MAX_COMMENT_LEN + 1];
} PasswordEntry;

/**
 * Validate string for valid characters (no control chars, nulls)
 * str: string to validate
 * max_len: maximum allowed length
 * allow_empty: whether empty strings are valid
 * Returns: 0 if valid, PWM_ERROR_INVALID_INPUT otherwise
 */
int validate_string(const char *str, size_t max_len, bool allow_empty);

/**
 * Create new password entry
 * entry: output entry structure
 * domain: service/domain name
 * username: username
 * password: password
 * comment: optional comment (can be NULL or empty)
 * Returns: 0 on success, error code on failure
 */
int entry_create(PasswordEntry *entry, const char *domain, const char *username,
                 const char *password, const char *comment);

/**
 * Validate password entry fields
 * entry: entry to validate
 * Returns: 0 if valid, error code on failure
 */
int entry_validate(const PasswordEntry *entry);

/**
 * Check if two entries match (same domain and username)
 * entry1: first entry
 * entry2: second entry
 * Returns: true if match, false otherwise
 */
bool entry_matches(const PasswordEntry *entry1, const PasswordEntry *entry2);

/**
 * Compare entry with domain and optional username
 * entry: entry to check
 * domain: domain to match
 * username: username to match (NULL to match any)
 * Returns: true if matches, false otherwise
 */
bool entry_matches_query(const PasswordEntry *entry, const char *domain,
                         const char *username);

/**
 * Clear entry (securely zero password)
 * entry: entry to clear
 */
void entry_clear(PasswordEntry *entry);

#endif /* ENTRY_H */

