#ifndef DATABASE_H
#define DATABASE_H

#include "common.h"
#include "entry.h"
#include "crypto.h"

// Database structure
typedef struct {
    PasswordEntry *entries;
    size_t count;
    size_t capacity;
    unsigned char salt[SALT_BYTES];
    char path[512];
} Database;

/**
 * Initialize empty database structure
 * db: database to initialize
 * path: path to database file
 */
void database_init(Database *db, const char *path);

/**
 * Free database memory
 * db: database to free
 */
void database_free(Database *db);

/**
 * Check if database file exists
 * path: path to check
 * Returns: true if exists, false otherwise
 */
bool database_exists(const char *path);

/**
 * Create new encrypted database with master password
 * path: database file path
 * master_password: master password
 * Returns: 0 on success, error code on failure
 */
int database_create(const char *path, const char *master_password);

/**
 * Load and decrypt database
 * db: output database structure
 * path: database file path
 * master_password: master password
 * Returns: 0 on success, error code on failure
 */
int database_load(Database *db, const char *path, const char *master_password);

/**
 * Save and encrypt database
 * db: database to save
 * master_password: master password
 * Returns: 0 on success, error code on failure
 */
int database_save(const Database *db, const char *master_password);

/**
 * Change master password (re-encrypt database)
 * db: database
 * old_password: current master password
 * new_password: new master password
 * Returns: 0 on success, error code on failure
 */
int database_change_password(Database *db, const char *old_password,
                              const char *new_password);

/**
 * Add entry to database
 * db: database
 * entry: entry to add
 * Returns: 0 on success, error code on failure
 */
int database_add_entry(Database *db, const PasswordEntry *entry);

/**
 * Get entry by index
 * db: database
 * index: entry index (0-based)
 * entry: output entry
 * Returns: 0 on success, PWM_ERROR_NOT_FOUND if index invalid
 */
int database_get_entry(const Database *db, size_t index, PasswordEntry *entry);

/**
 * Find entry by domain and optional username
 * db: database
 * domain: domain to search
 * username: username to search (NULL for any)
 * entry: output entry
 * Returns: 0 on success, PWM_ERROR_NOT_FOUND if not found
 */
int database_find_entry(const Database *db, const char *domain,
                        const char *username, PasswordEntry *entry);

/**
 * Remove entry by index
 * db: database
 * index: entry index to remove
 * Returns: 0 on success, error code on failure
 */
int database_remove_entry(Database *db, size_t index);

/**
 * Remove entry by domain and optional username
 * db: database
 * domain: domain to search
 * username: username to search (NULL for any)
 * Returns: 0 on success, PWM_ERROR_NOT_FOUND if not found
 */
int database_remove_entry_by_query(Database *db, const char *domain,
                                    const char *username);

/**
 * Ensure database file has secure permissions (0600)
 * path: file path to check
 * Returns: 0 on success, PWM_ERROR_PERMISSION on failure
 */
int ensure_secure_permissions(const char *path);

#endif /* DATABASE_H */

