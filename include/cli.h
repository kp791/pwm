#ifndef CLI_H
#define CLI_H

#include "common.h"
#include "database.h"

/**
 * Read password from terminal without echoing
 * prompt: prompt to display
 * password: output buffer
 * max_len: maximum password length
 * Returns: 0 on success, PWM_ERROR on failure
 */
int read_password(const char *prompt, char *password, size_t max_len);

/**
 * Parse query string in format "domain" or "domain:username"
 * query: query string
 * domain: output domain buffer
 * username: output username buffer (set to NULL if not provided)
 * Returns: 0 on success, PWM_ERROR_INVALID_INPUT on failure
 */
int parse_query(const char *query, char *domain, char **username);

/**
 * List all database entries (without passwords)
 * db: database to list
 */
void list_entries(const Database *db);

/**
 * Display single entry with password
 * entry: entry to display
 * index: entry index (for display)
 */
void display_entry(const PasswordEntry *entry, int index);

/**
 * Print only password (for piping)
 * entry: entry to print password from
 */
void print_password_only(const PasswordEntry *entry);

/**
 * Confirm action with user
 * prompt: confirmation prompt
 * Returns: true if confirmed, false otherwise
 */
bool confirm_action(const char *prompt);

/**
 * Print error message
 * error_code: error code
 * message: additional context message
 */
void pwm_print_error(int error_code, const char *message);

/**
 * Validate master password and optionally warn/block
 * password: password to validate
 * enforce: true to enforce minimum, false to warn only
 * Returns: 0 if valid or warning only, PWM_ERROR_INVALID_INPUT if enforced and too short
 */
int validate_master_password(const char *password, bool enforce);

/**
 * Read master password from file
 * path: path to password file
 * password: output buffer
 * max_len: maximum password length
 * Returns: 0 on success, error code on failure
 */
int read_password_from_file(const char *path, char *password, size_t max_len);


#endif /* CLI_H */

