#include "entry.h"
#include "crypto.h"

int validate_string(const char *str, size_t max_len, bool allow_empty) {
    if (!str) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    size_t len = strlen(str);
    
    if (!allow_empty && len == 0) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    if (len > max_len) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    // Check for control characters
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        if (c < 0x20 || c == 0x7F) {
            return PWM_ERROR_INVALID_INPUT;
        }
    }
    
    return PWM_SUCCESS;
}

int entry_create(PasswordEntry *entry, const char *domain, const char *username,
                 const char *password, const char *comment) {
    if (!entry || !domain || !username || !password) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    // Validate inputs
    if (validate_string(domain, MAX_DOMAIN_LEN, false) != PWM_SUCCESS) {
        return PWM_ERROR_INVALID_INPUT;
    }
    if (validate_string(username, MAX_USERNAME_LEN, false) != PWM_SUCCESS) {
        return PWM_ERROR_INVALID_INPUT;
    }
    if (validate_string(password, MAX_PASSWORD_LEN, false) != PWM_SUCCESS) {
        return PWM_ERROR_INVALID_INPUT;
    }
    if (comment && validate_string(comment, MAX_COMMENT_LEN, true) != PWM_SUCCESS) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    // Copy fields
    strncpy(entry->domain, domain, MAX_DOMAIN_LEN);
    entry->domain[MAX_DOMAIN_LEN] = '\0';
    
    strncpy(entry->username, username, MAX_USERNAME_LEN);
    entry->username[MAX_USERNAME_LEN] = '\0';
    
    strncpy(entry->password, password, MAX_PASSWORD_LEN);
    entry->password[MAX_PASSWORD_LEN] = '\0';
    
    if (comment) {
        strncpy(entry->comment, comment, MAX_COMMENT_LEN);
        entry->comment[MAX_COMMENT_LEN] = '\0';
    } else {
        entry->comment[0] = '\0';
    }
    
    return PWM_SUCCESS;
}

int entry_validate(const PasswordEntry *entry) {
    if (!entry) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    if (validate_string(entry->domain, MAX_DOMAIN_LEN, false) != PWM_SUCCESS) {
        return PWM_ERROR_INVALID_INPUT;
    }
    if (validate_string(entry->username, MAX_USERNAME_LEN, false) != PWM_SUCCESS) {
        return PWM_ERROR_INVALID_INPUT;
    }
    if (validate_string(entry->password, MAX_PASSWORD_LEN, false) != PWM_SUCCESS) {
        return PWM_ERROR_INVALID_INPUT;
    }
    if (validate_string(entry->comment, MAX_COMMENT_LEN, true) != PWM_SUCCESS) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    return PWM_SUCCESS;
}

bool entry_matches(const PasswordEntry *entry1, const PasswordEntry *entry2) {
    if (!entry1 || !entry2) {
        return false;
    }
    
    return strcmp(entry1->domain, entry2->domain) == 0 &&
           strcmp(entry1->username, entry2->username) == 0;
}

bool entry_matches_query(const PasswordEntry *entry, const char *domain,
                         const char *username) {
    if (!entry || !domain) {
        return false;
    }
    
    if (strcmp(entry->domain, domain) != 0) {
        return false;
    }
    
    if (username && strcmp(entry->username, username) != 0) {
        return false;
    }
    
    return true;
}

void entry_clear(PasswordEntry *entry) {
    if (entry) {
        secure_zero(entry->password, sizeof(entry->password));
    }
}

