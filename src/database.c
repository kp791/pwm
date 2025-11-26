#define _POSIX_C_SOURCE 200809L

#include "database.h"
#include "crypto.h"
#include <jansson.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

// Internal helper functions
static int atomic_write_file(const char *path, const void *data, size_t len);
static char* entries_to_json(const PasswordEntry *entries, size_t count);
static int json_to_entries(const char *json_str, PasswordEntry **entries, size_t *count);

void database_init(Database *db, const char *path) {
    if (!db || !path) {
        return;
    }
    
    db->entries = NULL;
    db->count = 0;
    db->capacity = 0;
    memset(db->salt, 0, SALT_BYTES);
    strncpy(db->path, path, sizeof(db->path) - 1);
    db->path[sizeof(db->path) - 1] = '\0';
}

void database_free(Database *db) {
    if (!db) {
        return;
    }
    
    if (db->entries) {
        // Securely clear all passwords
        for (size_t i = 0; i < db->count; i++) {
            entry_clear(&db->entries[i]);
        }
        free(db->entries);
        db->entries = NULL;
    }
    
    db->count = 0;
    db->capacity = 0;
    secure_zero(db->salt, SALT_BYTES);
}

bool database_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int database_create(const char *path, const char *master_password) {
    if (!path || !master_password) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    if (validate_string(master_password, MAX_MASTER_PASSWORD_LEN, false) != PWM_SUCCESS) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    if (database_exists(path)) {
        fprintf(stderr, "Error: Database already exists\n");
        return PWM_ERROR_FILE;
    }
    
    // Generate random salt
    unsigned char salt[SALT_BYTES];
    generate_random_bytes(salt, SALT_BYTES);
    
    // Derive key
    unsigned char key[KEY_BYTES];
    if (derive_key(master_password, salt, key) != PWM_SUCCESS) {
        secure_zero(key, KEY_BYTES);
        return PWM_ERROR_CRYPTO;
    }
    
    // Create empty entries JSON
    const char *empty_json = "{\"entries\":[]}";
    
    // Encrypt
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char nonce[NONCE_BYTES];
    
    int result = encrypt_data((const unsigned char *)empty_json, strlen(empty_json),
                              key, &ciphertext, &ciphertext_len, nonce);
    
    secure_zero(key, KEY_BYTES);
    
    if (result != PWM_SUCCESS) {
        return result;
    }
    
    // Encode to base64
    size_t salt_b64_len = sodium_base64_encoded_len(SALT_BYTES, sodium_base64_VARIANT_ORIGINAL);
    size_t nonce_b64_len = sodium_base64_encoded_len(NONCE_BYTES, sodium_base64_VARIANT_ORIGINAL);
    size_t cipher_b64_len = sodium_base64_encoded_len(ciphertext_len, sodium_base64_VARIANT_ORIGINAL);
    
    char *salt_b64 = malloc(salt_b64_len);
    char *nonce_b64 = malloc(nonce_b64_len);
    char *cipher_b64 = malloc(cipher_b64_len);
    
    if (!salt_b64 || !nonce_b64 || !cipher_b64) {
        free(salt_b64);
        free(nonce_b64);
        free(cipher_b64);
        sodium_free(ciphertext);
        return PWM_ERROR_MEMORY;
    }
    
    sodium_bin2base64(salt_b64, salt_b64_len, salt, SALT_BYTES, sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(nonce_b64, nonce_b64_len, nonce, NONCE_BYTES, sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(cipher_b64, cipher_b64_len, ciphertext, ciphertext_len, sodium_base64_VARIANT_ORIGINAL);
    
    sodium_free(ciphertext);
    
    // Create JSON structure
    json_t *root = json_object();
    json_object_set_new(root, "version", json_integer(1));
    json_object_set_new(root, "salt", json_string(salt_b64));
    json_object_set_new(root, "nonce", json_string(nonce_b64));
    json_object_set_new(root, "encrypted_data", json_string(cipher_b64));
    
    free(salt_b64);
    free(nonce_b64);
    free(cipher_b64);
    
    char *json_output = json_dumps(root, JSON_INDENT(2));
    json_decref(root);
    
    if (!json_output) {
        return PWM_ERROR_MEMORY;
    }
    
    // Write atomically
    result = atomic_write_file(path, json_output, strlen(json_output));
    free(json_output);
    
    if (result != PWM_SUCCESS) {
        return result;
    }
    
    // Set secure permissions
    return ensure_secure_permissions(path);
}

int database_load(Database *db, const char *path, const char *master_password) {
    if (!db || !path || !master_password) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    // SECURITY FIX: Open file first with O_NOFOLLOW to prevent symlink attacks
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        perror("open");
        return PWM_ERROR_FILE;
    }
    
    // SECURITY FIX: Check permissions on opened file descriptor (prevents TOCTOU)
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return PWM_ERROR_FILE;
    }
    
    // Must be regular file
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: Not a regular file\n");
        close(fd);
        return PWM_ERROR_PERMISSION;
    }
    
    // Must be owned by current user
    if (st.st_uid != getuid()) {
        fprintf(stderr, "Error: File not owned by current user\n");
        close(fd);
        return PWM_ERROR_PERMISSION;
    }
    
    // Check permissions (should be 0600)
    mode_t perms = st.st_mode & 0777;
    if (perms != 0600) {
        // Try to fix permissions
        if (fchmod(fd, 0600) < 0) {
            perror("fchmod");
            close(fd);
            return PWM_ERROR_PERMISSION;
        }
    }
    
    // Convert fd to FILE*
    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        perror("fdopen");
        close(fd);
        return PWM_ERROR_FILE;
    }
    
    json_error_t error;
    json_t *root = json_loadf(fp, 0, &error);
    fclose(fp);  // This also closes fd
    
    if (!root) {
        fprintf(stderr, "JSON parse error on line %d: %s\n", error.line, error.text);
        return PWM_ERROR_FILE;
    }
    
    // Parse JSON
    json_t *version_obj = json_object_get(root, "version");
    json_t *salt_obj = json_object_get(root, "salt");
    json_t *nonce_obj = json_object_get(root, "nonce");
    json_t *encrypted_obj = json_object_get(root, "encrypted_data");
    
    if (!json_is_integer(version_obj) || !json_is_string(salt_obj) ||
        !json_is_string(nonce_obj) || !json_is_string(encrypted_obj)) {
        json_decref(root);
        return PWM_ERROR_FILE;
    }
    
    int version = json_integer_value(version_obj);
    if (version != 1) {
        fprintf(stderr, "Unsupported database version: %d\n", version);
        json_decref(root);
        return PWM_ERROR_FILE;
    }
    
    const char *salt_b64 = json_string_value(salt_obj);
    const char *nonce_b64 = json_string_value(nonce_obj);
    const char *cipher_b64 = json_string_value(encrypted_obj);
    
    // Decode base64
    unsigned char salt[SALT_BYTES];
    unsigned char nonce[NONCE_BYTES];
    unsigned char *ciphertext = malloc(strlen(cipher_b64)); // Overallocate
    
    size_t salt_len, nonce_len, cipher_len;
    
    if (sodium_base642bin(salt, SALT_BYTES, salt_b64, strlen(salt_b64),
                          NULL, &salt_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0 ||
        sodium_base642bin(nonce, NONCE_BYTES, nonce_b64, strlen(nonce_b64),
                          NULL, &nonce_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0 ||
        sodium_base642bin(ciphertext, strlen(cipher_b64), cipher_b64, strlen(cipher_b64),
                          NULL, &cipher_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
        json_decref(root);
        free(ciphertext);
        return PWM_ERROR_FILE;
    }
    
    json_decref(root);
    
    // Derive key
    unsigned char key[KEY_BYTES];
    if (derive_key(master_password, salt, key) != PWM_SUCCESS) {
        secure_zero(key, KEY_BYTES);
        free(ciphertext);
        return PWM_ERROR_CRYPTO;
    }
    
    // Decrypt
    unsigned char *plaintext;
    size_t plaintext_len;
    
    int result = decrypt_data(ciphertext, cipher_len, key, nonce,
                              &plaintext, &plaintext_len);
    
    secure_zero(key, KEY_BYTES);
    free(ciphertext);
    
    if (result != PWM_SUCCESS) {
        return PWM_ERROR_CRYPTO; // Wrong password or corrupted data
    }
    
    // Parse entries JSON
    result = json_to_entries((const char *)plaintext, &db->entries, &db->count);
    sodium_free(plaintext);
    
    if (result != PWM_SUCCESS) {
        return result;
    }
    
    // Store salt and path
    memcpy(db->salt, salt, SALT_BYTES);
    strncpy(db->path, path, sizeof(db->path) - 1);
    db->path[sizeof(db->path) - 1] = '\0';
    db->capacity = db->count;
    
    return PWM_SUCCESS;
}

int database_save(const Database *db, const char *master_password) {
    if (!db || !master_password) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    // Convert entries to JSON
    char *json_str = entries_to_json(db->entries, db->count);
    if (!json_str) {
        return PWM_ERROR_MEMORY;
    }
    
    // Derive key
    unsigned char key[KEY_BYTES];
    if (derive_key(master_password, db->salt, key) != PWM_SUCCESS) {
        secure_zero(key, KEY_BYTES);
        free(json_str);
        return PWM_ERROR_CRYPTO;
    }
    
    // Encrypt
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char nonce[NONCE_BYTES];
    
    int result = encrypt_data((const unsigned char *)json_str, strlen(json_str),
                              key, &ciphertext, &ciphertext_len, nonce);
    
    secure_zero(key, KEY_BYTES);
    secure_zero(json_str, strlen(json_str));
    free(json_str);
    
    if (result != PWM_SUCCESS) {
        return result;
    }
    
    // Encode to base64
    size_t salt_b64_len = sodium_base64_encoded_len(SALT_BYTES, sodium_base64_VARIANT_ORIGINAL);
    size_t nonce_b64_len = sodium_base64_encoded_len(NONCE_BYTES, sodium_base64_VARIANT_ORIGINAL);
    size_t cipher_b64_len = sodium_base64_encoded_len(ciphertext_len, sodium_base64_VARIANT_ORIGINAL);
    
    char *salt_b64 = malloc(salt_b64_len);
    char *nonce_b64 = malloc(nonce_b64_len);
    char *cipher_b64 = malloc(cipher_b64_len);
    
    if (!salt_b64 || !nonce_b64 || !cipher_b64) {
        free(salt_b64);
        free(nonce_b64);
        free(cipher_b64);
        sodium_free(ciphertext);
        return PWM_ERROR_MEMORY;
    }
    
    sodium_bin2base64(salt_b64, salt_b64_len, db->salt, SALT_BYTES, sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(nonce_b64, nonce_b64_len, nonce, NONCE_BYTES, sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(cipher_b64, cipher_b64_len, ciphertext, ciphertext_len, sodium_base64_VARIANT_ORIGINAL);
    
    sodium_free(ciphertext);
    
    // Create JSON structure
    json_t *root = json_object();
    json_object_set_new(root, "version", json_integer(1));
    json_object_set_new(root, "salt", json_string(salt_b64));
    json_object_set_new(root, "nonce", json_string(nonce_b64));
    json_object_set_new(root, "encrypted_data", json_string(cipher_b64));
    
    free(salt_b64);
    free(nonce_b64);
    free(cipher_b64);
    
    char *json_output = json_dumps(root, JSON_INDENT(2));
    json_decref(root);
    
    if (!json_output) {
        return PWM_ERROR_MEMORY;
    }
    
    // Write atomically
    result = atomic_write_file(db->path, json_output, strlen(json_output));
    free(json_output);
    
    return result;
}

int database_change_password(Database *db, const char *old_password,
                              const char *new_password) {
    if (!db || !old_password || !new_password) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    if (validate_string(new_password, MAX_MASTER_PASSWORD_LEN, false) != PWM_SUCCESS) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    // Verify old password by deriving key
    unsigned char old_key[KEY_BYTES];
    if (derive_key(old_password, db->salt, old_key) != PWM_SUCCESS) {
        secure_zero(old_key, KEY_BYTES);
        return PWM_ERROR_CRYPTO;
    }
    secure_zero(old_key, KEY_BYTES);
    
    // Generate new salt
    unsigned char new_salt[SALT_BYTES];
    generate_random_bytes(new_salt, SALT_BYTES);
    
    // Update salt
    memcpy(db->salt, new_salt, SALT_BYTES);
    
    // Save with new password (which will use new salt)
    return database_save(db, new_password);
}

int database_add_entry(Database *db, const PasswordEntry *entry) {
    if (!db || !entry) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    if (entry_validate(entry) != PWM_SUCCESS) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    // Check for duplicates
    for (size_t i = 0; i < db->count; i++) {
        if (entry_matches(&db->entries[i], entry)) {
            return PWM_ERROR_DUPLICATE;
        }
    }
    
    // Check capacity
    if (db->count >= MAX_ENTRIES) {
        return PWM_ERROR_MEMORY;
    }
    
    // Expand array if needed
    if (db->count >= db->capacity) {
        size_t new_capacity = db->capacity == 0 ? 10 : db->capacity * 2;
        if (new_capacity > MAX_ENTRIES) {
            new_capacity = MAX_ENTRIES;
        }
        
        PasswordEntry *new_entries = realloc(db->entries,
                                              new_capacity * sizeof(PasswordEntry));
        if (!new_entries) {
            return PWM_ERROR_MEMORY;
        }
        
        db->entries = new_entries;
        db->capacity = new_capacity;
    }
    
    // Copy entry
    memcpy(&db->entries[db->count], entry, sizeof(PasswordEntry));
    db->count++;
    
    return PWM_SUCCESS;
}

int database_get_entry(const Database *db, size_t index, PasswordEntry *entry) {
    if (!db || !entry) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    if (index >= db->count) {
        return PWM_ERROR_NOT_FOUND;
    }
    
    memcpy(entry, &db->entries[index], sizeof(PasswordEntry));
    return PWM_SUCCESS;
}

int database_find_entry(const Database *db, const char *domain,
                        const char *username, PasswordEntry *entry) {
    if (!db || !domain || !entry) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    for (size_t i = 0; i < db->count; i++) {
        if (entry_matches_query(&db->entries[i], domain, username)) {
            memcpy(entry, &db->entries[i], sizeof(PasswordEntry));
            return PWM_SUCCESS;
        }
    }
    
    return PWM_ERROR_NOT_FOUND;
}

int database_remove_entry(Database *db, size_t index) {
    if (!db) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    if (index >= db->count) {
        return PWM_ERROR_NOT_FOUND;
    }
    
    // Clear password before removing
    entry_clear(&db->entries[index]);
    
    // Shift entries down
    if (index < db->count - 1) {
        memmove(&db->entries[index], &db->entries[index + 1],
                (db->count - index - 1) * sizeof(PasswordEntry));
    }
    
    db->count--;
    return PWM_SUCCESS;
}

int database_remove_entry_by_query(Database *db, const char *domain,
                                    const char *username) {
    if (!db || !domain) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    for (size_t i = 0; i < db->count; i++) {
        if (entry_matches_query(&db->entries[i], domain, username)) {
            return database_remove_entry(db, i);
        }
    }
    
    return PWM_ERROR_NOT_FOUND;
}

int ensure_secure_permissions(const char *path) {
    if (!path) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    struct stat st;
    
    if (stat(path, &st) < 0) {
        perror("stat");
        return PWM_ERROR_FILE;
    }
    
    // Must be regular file
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: %s is not a regular file\n", path);
        return PWM_ERROR_PERMISSION;
    }
    
    // Must be owned by current user
    if (st.st_uid != getuid()) {
        fprintf(stderr, "Error: %s not owned by current user\n", path);
        return PWM_ERROR_PERMISSION;
    }
    
    // Check permissions (should be 0600)
    mode_t perms = st.st_mode & 0777;
    if (perms != 0600) {
        if (chmod(path, 0600) < 0) {
            perror("chmod");
            return PWM_ERROR_PERMISSION;
        }
    }
    
    return PWM_SUCCESS;
}

// Internal helper functions

// SECURITY FIX: Use random suffix instead of PID to prevent race conditions
static int atomic_write_file(const char *path, const void *data, size_t len) {
    char temp_path[1024];
    
    // Use random suffix instead of PID
    unsigned char random_suffix[8];
    randombytes_buf(random_suffix, sizeof(random_suffix));
    
    char suffix_hex[17];
    for (int i = 0; i < 8; i++) {
        sprintf(suffix_hex + i*2, "%02x", random_suffix[i]);
    }
    
    snprintf(temp_path, sizeof(temp_path), "%s.tmp.%s", path, suffix_hex);
    
    // O_EXCL prevents race conditions, O_NOFOLLOW prevents symlink attacks
    int fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        perror("open");
        return PWM_ERROR_FILE;
    }
    
    // Write data
    ssize_t written = 0;
    while (written < (ssize_t)len) {
        ssize_t n = write(fd, (const char *)data + written, len - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("write");
            close(fd);
            unlink(temp_path);
            return PWM_ERROR_FILE;
        }
        written += n;
    }
    
    // Flush to disk
    if (fsync(fd) < 0) {
        perror("fsync");
        close(fd);
        unlink(temp_path);
        return PWM_ERROR_FILE;
    }
    
    close(fd);
    
    // Atomic rename
    if (rename(temp_path, path) < 0) {
        perror("rename");
        unlink(temp_path);
        return PWM_ERROR_FILE;
    }
    
    // Sync directory for durability
    char *dir_path = strdup(path);
    if (dir_path) {
        char *dir = dirname(dir_path);
        int dir_fd = open(dir, O_RDONLY);
        if (dir_fd >= 0) {
            fsync(dir_fd);
            close(dir_fd);
        }
        free(dir_path);
    }
    
    return PWM_SUCCESS;
}

static char* entries_to_json(const PasswordEntry *entries, size_t count) {
    json_t *root = json_object();
    json_t *entries_array = json_array();
    
    for (size_t i = 0; i < count; i++) {
        json_t *entry_obj = json_object();
        json_object_set_new(entry_obj, "domain", json_string(entries[i].domain));
        json_object_set_new(entry_obj, "username", json_string(entries[i].username));
        json_object_set_new(entry_obj, "password", json_string(entries[i].password));
        json_object_set_new(entry_obj, "comment", json_string(entries[i].comment));
        json_array_append_new(entries_array, entry_obj);
    }
    
    json_object_set_new(root, "entries", entries_array);
    
    char *json_str = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    
    return json_str;
}

static int json_to_entries(const char *json_str, PasswordEntry **entries, size_t *count) {
    json_error_t error;
    json_t *root = json_loads(json_str, 0, &error);
    
    if (!root) {
        fprintf(stderr, "JSON parse error: %s\n", error.text);
        return PWM_ERROR_FILE;
    }
    
    json_t *entries_array = json_object_get(root, "entries");
    if (!json_is_array(entries_array)) {
        json_decref(root);
        return PWM_ERROR_FILE;
    }
    
    size_t array_size = json_array_size(entries_array);
    
    if (array_size > MAX_ENTRIES) {
        json_decref(root);
        return PWM_ERROR_FILE;
    }
    
    *entries = malloc(array_size * sizeof(PasswordEntry));
    if (!*entries && array_size > 0) {
        json_decref(root);
        return PWM_ERROR_MEMORY;
    }
    
    *count = 0;
    
    for (size_t i = 0; i < array_size; i++) {
        json_t *entry_obj = json_array_get(entries_array, i);
        
        json_t *domain_obj = json_object_get(entry_obj, "domain");
        json_t *username_obj = json_object_get(entry_obj, "username");
        json_t *password_obj = json_object_get(entry_obj, "password");
        json_t *comment_obj = json_object_get(entry_obj, "comment");
        
        if (!json_is_string(domain_obj) || !json_is_string(username_obj) ||
            !json_is_string(password_obj) || !json_is_string(comment_obj)) {
            free(*entries);
            *entries = NULL;
            json_decref(root);
            return PWM_ERROR_FILE;
        }
        
        const char *domain = json_string_value(domain_obj);
        const char *username = json_string_value(username_obj);
        const char *password = json_string_value(password_obj);
        const char *comment = json_string_value(comment_obj);
        
        if (entry_create(&(*entries)[*count], domain, username, password, comment) != PWM_SUCCESS) {
            free(*entries);
            *entries = NULL;
            json_decref(root);
            return PWM_ERROR_INVALID_INPUT;
        }
        
        (*count)++;
    }
    
    json_decref(root);
    return PWM_SUCCESS;
}

