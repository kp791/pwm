#define _POSIX_C_SOURCE 200809L

#include "cli.h"
#include "crypto.h"
#include <termios.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>

int read_password(const char *prompt, char *password, size_t max_len) {
    if (!prompt || !password || max_len == 0) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    struct termios old_term, new_term;
    
    // Get current terminal settings
    if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
        perror("tcgetattr");
        return PWM_ERROR;
    }
    
    // Disable echo
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
        perror("tcsetattr");
        return PWM_ERROR;
    }
    
    // Display prompt
    printf("%s", prompt);
    fflush(stdout);
    
    // Read password
    int result = PWM_SUCCESS;
    if (!fgets(password, max_len, stdin)) {
        result = PWM_ERROR;
    }
    
    // CRITICAL: Always restore terminal, even on error
    if (tcsetattr(STDIN_FILENO, TCSANOW, &old_term) != 0) {
        perror("tcsetattr restore failed");
        // Try one more time with TCSAFLUSH
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
    }
    
    printf("\n");
    
    if (result != PWM_SUCCESS) {
        return result;
    }
    
    // Remove newline
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
    }
    
    return PWM_SUCCESS;
}

int parse_query(const char *query, char *domain, char **username) {
    if (!query || !domain || !username) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    *username = NULL;
    
    // Find colon separator
    const char *colon = strchr(query, ':');
    
    if (colon) {
        // Has username part
        size_t domain_len = colon - query;
        
        // SECURITY FIX: Changed from > to >=
        if (domain_len == 0 || domain_len >= MAX_DOMAIN_LEN) {
            return PWM_ERROR_INVALID_INPUT;
        }
        
        strncpy(domain, query, domain_len);
        domain[domain_len] = '\0';
        
        const char *user_part = colon + 1;
        size_t user_len = strlen(user_part);
        
        if (user_len == 0 || user_len >= MAX_USERNAME_LEN) {
            return PWM_ERROR_INVALID_INPUT;
        }
        
        *username = strdup(user_part);
        if (!*username) {
            return PWM_ERROR_MEMORY;
        }
    } else {
        // Domain only
        size_t domain_len = strlen(query);
        
        if (domain_len == 0 || domain_len >= MAX_DOMAIN_LEN) {
            return PWM_ERROR_INVALID_INPUT;
        }
        
        strcpy(domain, query);
    }
    
    // Validate parsed values
    if (validate_string(domain, MAX_DOMAIN_LEN, false) != PWM_SUCCESS) {
        if (*username) free(*username);
        return PWM_ERROR_INVALID_INPUT;
    }
    
    if (*username && validate_string(*username, MAX_USERNAME_LEN, false) != PWM_SUCCESS) {
        free(*username);
        *username = NULL;
        return PWM_ERROR_INVALID_INPUT;
    }
    
    return PWM_SUCCESS;
}

void list_entries(const Database *db) {
    if (!db) {
        return;
    }
    
    if (db->count == 0) {
        printf("No entries found.\n");
        return;
    }
    
    // Test without colors first
    printf("\nPassword Entries (%zu total):\n\n", db->count);
    printf("%-5s %-30s %-30s %-40s\n", "ID", "Domain", "Username", "Comment");
    printf("-----------------------------------------------------\n");
    
    for (size_t i = 0; i < db->count; i++) {
        const PasswordEntry *entry = &db->entries[i];
            printf("%-5zu %-30s %-30s %-40s\n",
                i, entry->domain, entry->username, entry->comment);
        
    }
    printf("\n");
}

void display_entry(const PasswordEntry *entry, int index) {
    if (!entry) {
        return;
    }
    
    printf("\n""Entry Details:""\n");
    if (index >= 0) {
        printf("  ID:       %d\n", index);
    }
    printf("  Domain:   %s\n", entry->domain);
    printf("  Username: %s\n", entry->username);
    printf("  Password: %s\n", entry->password);
    if (strlen(entry->comment) > 0) {
        printf("  Comment:  %s\n", entry->comment);
    }
    printf("\n");
}

// NEW: Print only password for piping
void print_password_only(const PasswordEntry *entry) {
    if (!entry) {
        return;
    }
    printf("%s\n", entry->password);
}

bool confirm_action(const char *prompt) {
    if (!prompt) {
        return false;
    }
    
    printf("%s (y/n): ", prompt);
    fflush(stdout);
    
    char response[10];
    if (!fgets(response, sizeof(response), stdin)) {
        return false;
    }
    
    return (response[0] == 'y' || response[0] == 'Y');
}

void pwm_print_error(int error_code, const char *message) {
    fprintf(stderr,"Error: ");
    
    switch (error_code) {
        case PWM_ERROR_INVALID_INPUT:
            fprintf(stderr, "Invalid input");
            break;
        case PWM_ERROR_NOT_FOUND:
            fprintf(stderr, "Entry not found");
            break;
        case PWM_ERROR_DUPLICATE:
            fprintf(stderr, "Duplicate entry");
            break;
        case PWM_ERROR_CRYPTO:
            fprintf(stderr, "Cryptographic error (wrong password or corrupted data)");
            break;
        case PWM_ERROR_FILE:
            fprintf(stderr, "File operation error");
            break;
        case PWM_ERROR_PERMISSION:
            fprintf(stderr, "Permission error");
            break;
        case PWM_ERROR_MEMORY:
            fprintf(stderr, "Memory allocation error");
            break;
        default:
            fprintf(stderr, "Unknown error");
            break;
    }
    
    if (message) {
        fprintf(stderr, ": %s", message);
    }
    
    fprintf(stderr, "\n");
}

int validate_master_password(const char *password, bool enforce) {
    if (!password) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    size_t len = strlen(password);
    
    // Check against minimum length
    if (len < MIN_MASTER_PASSWORD_LEN) {
        fprintf(stderr,"Warning: Master password is only %zu characters. ", len);
        fprintf(stderr, "Recommended minimum is %d characters.""\n", 
                MIN_MASTER_PASSWORD_LEN);
        
        if (enforce) {
            fprintf(stderr,"Error: Master password too short (enforcement enabled).""\n");
            return PWM_ERROR_INVALID_INPUT;
        } else {
            fprintf(stderr,"Continuing anyway (enforcement disabled)...""\n");
        }
    }
    
    // Provide strength feedback for good passwords
    if (len >= MIN_MASTER_PASSWORD_LEN && len < 16) {
        fprintf(stderr,"Info: Password strength is acceptable. " 
                "Consider using 16+ characters for better security.""\n");
    } else if (len >= 16) {
        fprintf(stderr,"Info: Good password length!""\n");
    }
    
    return PWM_SUCCESS;
}

int read_password_from_file(const char *path, char *password, size_t max_len) {
    if (!path || !password || max_len == 0) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    // Open and check permissions
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        perror("open password file");
        return PWM_ERROR_FILE;
    }
    
    // Check file permissions (should be 0400 or 0600)
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return PWM_ERROR_FILE;
    }
    
    // Warn if permissions are too open
    if ((st.st_mode & 0077) != 0) {
        fprintf(stderr,"Warning: Password file has insecure permissions. " 
                "Recommend: chmod 400 %s""\n", path);
    }
    
    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        perror("fdopen");
        close(fd);
        return PWM_ERROR_FILE;
    }
    
    if (!fgets(password, max_len, fp)) {
        fclose(fp);
        return PWM_ERROR_FILE;
    }
    
    fclose(fp);
    
    // Remove newline
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
    }
    
    return PWM_SUCCESS;
}


