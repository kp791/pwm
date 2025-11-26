#include "common.h"
#include "crypto.h"
#include "database.h"
#include "entry.h"
#include "cli.h"
#include <getopt.h>

// Global options for master password
static const char *master_password_file = NULL;
static const char *master_password_arg = NULL;

static void print_usage(const char *program_name);
static int cmd_init(const char *db_path);
static int cmd_add(const char *db_path, int argc, char **argv);
static int cmd_list(const char *db_path);
static int cmd_get(const char *db_path, const char *query, bool password_only);
static int cmd_remove(const char *db_path, const char *query);
static int cmd_change_password(const char *db_path);

// Helper to get master password from various sources
static int get_master_password(char *password, size_t max_len, const char *prompt) {
    // Priority: 1. --password, 2. --password-file, 3. PWM_MASTER_PASSWORD env, 4. prompt
    
    // Option 1: Command-line argument (least secure)
    if (master_password_arg) {
        fprintf(stderr, "Warning: Passing password via command line is insecure!" "\n");
        if (strlen(master_password_arg) >= max_len) {
            fprintf(stderr, "Error: Password too long\n");
            return PWM_ERROR_INVALID_INPUT;
        }
        strncpy(password, master_password_arg, max_len - 1);
        password[max_len - 1] = '\0';
        return PWM_SUCCESS;
    }
    
    // Option 2: Password file (secure if file permissions are correct)
    if (master_password_file) {
        return read_password_from_file(master_password_file, password, max_len);
    }
    
    // Option 3: Environment variable (moderately secure)
    const char *env_password = getenv("PWM_MASTER_PASSWORD");
    if (env_password) {
        fprintf(stderr, "Info: Using master password from PWM_MASTER_PASSWORD environment variable" "\n");
        if (strlen(env_password) >= max_len) {
            fprintf(stderr, "Error: Password too long\n");
            return PWM_ERROR_INVALID_INPUT;
        }
        strncpy(password, env_password, max_len - 1);
        password[max_len - 1] = '\0';
        return PWM_SUCCESS;
    }
    
    // Option 4: Interactive prompt (most secure)
    return read_password(prompt, password, max_len);
}

int main(int argc, char **argv) {
    // Initialize crypto library
    if (crypto_init() != PWM_SUCCESS) {
        return EXIT_FAILURE;
    }
    
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    const char *db_path = getenv("PWM_DB_PATH");
    if (!db_path) {
        db_path = DEFAULT_DB_PATH;
    }
    
    // Parse global options before command
    int opt_index = 1;
    while (opt_index < argc && argv[opt_index][0] == '-' && argv[opt_index][1] == '-') {
        if (strncmp(argv[opt_index], "--password-file=", 16) == 0) {
            master_password_file = argv[opt_index] + 16;
            opt_index++;
        } else if (strncmp(argv[opt_index], "--password=", 11) == 0) {
            master_password_arg = argv[opt_index] + 11;
            fprintf(stderr, "Warning: Password visible in process list and shell history!" "\n");
            opt_index++;
        } else {
            break;
        }
    }
    
    if (opt_index >= argc) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    const char *command = argv[opt_index];
    opt_index++;
    
    // Check for --password-only flag (for piping)
    bool password_only = false;
    if (opt_index < argc && (strcmp(argv[opt_index], "--password-only") == 0 || 
                             strcmp(argv[opt_index], "-p") == 0)) {
        password_only = true;
        opt_index++;
    }
    
    if (strcmp(command, "init") == 0) {
        return cmd_init(db_path);
    } else if (strcmp(command, "add") == 0) {
        return cmd_add(db_path, argc - opt_index, argv + opt_index);
    } else if (strcmp(command, "ls") == 0 || strcmp(command, "list") == 0) {
        return cmd_list(db_path);
    } else if (strcmp(command, "get") == 0) {
        if (opt_index >= argc) {
            fprintf(stderr, "Usage: %s get <index|domain[:username]> [--password-only|-p]\n", argv[0]);
            return EXIT_FAILURE;
        }
        return cmd_get(db_path, argv[opt_index], password_only);
    } else if (strcmp(command, "rm") == 0 || strcmp(command, "remove") == 0) {
        if (opt_index >= argc) {
            fprintf(stderr, "Usage: %s rm <index|domain[:username]>\n", argv[0]);
            return EXIT_FAILURE;
        }
        return cmd_remove(db_path, argv[opt_index]);
    } else if (strcmp(command, "change-password") == 0) {
        return cmd_change_password(db_path);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

static void print_usage(const char *program_name) {
    printf("Usage: %s [global-options] <command> [options]\n\n", program_name);
    printf("Global Options (before command):\n");
    printf("  --password-file=PATH              Read master password from file\n");
    printf("  --password=PASS                   Master password (INSECURE, visible in ps)\n");
    printf("\nCommands:\n");
    printf("  init                                  Initialize new password database\n");
    printf("  add <domain> [username] [opts]        Add new entry\n");
    printf("    -gp, --generate-password            Generate secure password\n");
    printf("    -gu, --generate-username            Generate random username\n");
    printf("    -c, --comment <text>                Add comment\n");
    printf("    -l, --length <num>                  Password length (default: 24)\n");
    printf("    -s, --symbols                       Include symbols in generated password\n");
    printf("    -v, --show                          Show generated credentials (default: hidden)\n");
    printf("  ls, list                              List all entries (without passwords)\n");
    printf("  get <index|domain[:username]>         Get entry details with password\n");
    printf("    -p, --password-only                 Output only password (for piping)\n");
    printf("  rm <index|domain[:username]>          Remove entry\n");
    printf("  change-password                       Change master password\n");
    printf("\nEnvironment Variables:\n");
    printf("  PWM_DB_PATH                           Database file path (default: %s)\n", DEFAULT_DB_PATH);
    printf("  PWM_MASTER_PASSWORD                   Master password (for non-interactive use)\n");
    printf("\nExamples:\n");
    printf("  # Add with explicit username\n");
    printf("  %s add gmail user@example.com -gp\n\n", program_name);
    printf("  # Generate username (no username argument needed)\n");
    printf("  %s add github -gu -gp\n\n", program_name);
    printf("  # Generate both username and password\n");
    printf("  %s add randomsite.com -gu -gp -s -l 32\n\n", program_name);
    printf("  # Show generated credentials\n");
    printf("  %s add test.com -gu -gp --show\n\n", program_name);
    printf("  echo 'my_master_pass' > ~/.pwm_master\n");
    printf("  chmod 400 ~/.pwm_master\n");
    printf("  %s --password-file=~/.pwm_master get 0 -p\n\n", program_name);
    printf("  # Using environment variable\n");
    printf("  export PWM_MASTER_PASSWORD='my_master_pass'\n");
    printf("  %s get gmail -p\n\n", program_name);
    printf("  # In scripts (password file method)\n");
    printf("  PASSWORD=$(pwm --password-file=~/.pwm_master get github -p)\n");
    printf("  curl -u user:$PASSWORD https://api.github.com/user\n\n");
    printf("  # One-liner with environment variable\n");
    printf("  curl -u user:$(PWM_MASTER_PASSWORD='pass' pwm get 0 -p) https://example.com\n");
}

static int cmd_init(const char *db_path) {
    if (database_exists(db_path)) {
        fprintf(stderr, "Error: Database already exists at %s\n", db_path);
        return EXIT_FAILURE;
    }
    
    char master_password[MAX_MASTER_PASSWORD_LEN + 1];
    char confirm_password[MAX_MASTER_PASSWORD_LEN + 1];
    
    if (read_password("Enter master password: ", master_password, 
                      sizeof(master_password)) != PWM_SUCCESS) {
        fprintf(stderr, "Error: Failed to read password\n");
        return EXIT_FAILURE;
    }
    
    // Validate master password with configurable enforcement
    if (validate_master_password(master_password, ENFORCE_MASTER_PASSWORD_MIN) != PWM_SUCCESS) {
        secure_zero(master_password, sizeof(master_password));
        return EXIT_FAILURE;
    }
    
    if (read_password("Confirm master password: ", confirm_password, 
                      sizeof(confirm_password)) != PWM_SUCCESS) {
        secure_zero(master_password, sizeof(master_password));
        fprintf(stderr, "Error: Failed to read password\n");
        return EXIT_FAILURE;
    }
    
    if (strcmp(master_password, confirm_password) != 0) {
        fprintf(stderr, "Error: Passwords do not match\n");
        secure_zero(master_password, sizeof(master_password));
        secure_zero(confirm_password, sizeof(confirm_password));
        return EXIT_FAILURE;
    }
    
    secure_zero(confirm_password, sizeof(confirm_password));
    
    int result = database_create(db_path, master_password);
    secure_zero(master_password, sizeof(master_password));
    
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, "Failed to create database");
        return EXIT_FAILURE;
    }
    
    printf("Database initialized successfully at %s\n", db_path);
    return EXIT_SUCCESS;
}

static int cmd_add(const char *db_path, int argc, char **argv) {
    if (argc < 1) {
        fprintf(stderr, "Usage: pwm add <domain> [username] [options]\n");
        fprintf(stderr, "       pwm add <domain> -gu [options]  # username will be generated\n");
        return EXIT_FAILURE;
    }
    
    const char *domain = argv[0];
    const char *username = NULL;
    
    bool gen_password = false;
    bool gen_username = false;
    bool use_symbols = false;
    bool show_generated = false;
    int password_length = DEFAULT_PASSWORD_LENGTH;
    const char *comment = "";
    const char *password_arg = NULL;
    
    // First pass: manually scan for our custom flags and remove them
    int new_argc = 1; // Start with domain
    char *new_argv[100]; // Temporary array for filtered args
    new_argv[0] = argv[0]; // Keep domain
    
    int opt_start = 1;
    bool username_provided = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-gu") == 0 || strcmp(argv[i], "--generate-username") == 0) {
            gen_username = true;
            // Don't add to new_argv
        } else if (strcmp(argv[i], "-gp") == 0 || strcmp(argv[i], "--generate-password") == 0) {
            gen_password = true;
            // Don't add to new_argv
        } else if (strcmp(argv[i], "-gpgu") == 0 || strcmp(argv[i], "-gugp") == 0) {
            gen_password = true;
            gen_username = true;
            // Don't add to new_argv
        } else if (argv[i][0] == '-') {
            // Other flag, keep it for getopt
            new_argv[new_argc++] = argv[i];
        } else if (!username_provided && !gen_username && opt_start == 1) {
            // This is the username (second positional arg)
            username = argv[i];
            username_provided = true;
            opt_start = 2;
        } else {
            // Other argument
            new_argv[new_argc++] = argv[i];
        }
    }
    
    // Check if username is required
    if (!gen_username && !username_provided) {
        fprintf(stderr, "Error: username required (or use -gu to generate)\n");
        fprintf(stderr, "Usage: pwm add <domain> <username> [options]\n");
        fprintf(stderr, "       pwm add <domain> -gu [options]\n");
        return EXIT_FAILURE;
    }
    
    // Warn if both provided
    if (username_provided && gen_username) {
        fprintf(stderr, "Warning: Username provided but -gu flag set. " 
                "Ignoring provided username and generating new one." "\n");
        username = NULL;
    }
    
    // Now parse remaining options with getopt
    struct option long_options[] = {
        {"comment", required_argument, 0, 'c'},
        {"length", required_argument, 0, 'l'},
        {"symbols", no_argument, 0, 's'},
        {"show", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 1; // Reset getopt
    
    while ((opt = getopt_long(new_argc, new_argv, "c:l:sv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                comment = optarg;
                break;
            case 'l':
                {
                    char *endptr;
                    long temp = strtol(optarg, &endptr, 10);
                    if (*endptr != '\0' || temp <= 0 || temp > MAX_PASSWORD_LEN) {
                        fprintf(stderr, "Error: Invalid password length\n");
                        return EXIT_FAILURE;
                    }
                    password_length = (int)temp;
                }
                break;
            case 's':
                use_symbols = true;
                break;
            case 'v':
                show_generated = true;
                break;
            case '?':
                return EXIT_FAILURE;
            default:
                break;
        }
    }
    
    // Load database
    char master_password[MAX_MASTER_PASSWORD_LEN + 1];
    if (get_master_password(master_password, sizeof(master_password), 
                           "Master password: ") != PWM_SUCCESS) {
        fprintf(stderr, "Error: Failed to read password\n");
        return EXIT_FAILURE;
    }
    
    Database db;
    database_init(&db, db_path);
    
    int result = database_load(&db, db_path, master_password);
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, "Failed to load database");
        secure_zero(master_password, sizeof(master_password));
        return EXIT_FAILURE;
    }
    
    // Generate username if requested
    char generated_username[MAX_USERNAME_LEN + 1];
    if (gen_username) {
        if (generate_username(generated_username, 12) != PWM_SUCCESS) {
            fprintf(stderr, "Error: Failed to generate username\n");
            database_free(&db);
            secure_zero(master_password, sizeof(master_password));
            return EXIT_FAILURE;
        }
        username = generated_username;
        if (show_generated) {
            printf("Generated username: %s\n", username);
        }
    }
    
    // At this point username must be set
    if (!username) {
        fprintf(stderr, "Error: Username not provided and -gu not specified\n");
        database_free(&db);
        secure_zero(master_password, sizeof(master_password));
        return EXIT_FAILURE;
    }
    
    // Get or generate password
    char password_buf[MAX_PASSWORD_LEN + 1];
    if (gen_password) {
        if (generate_password(password_buf, password_length, use_symbols) != PWM_SUCCESS) {
            fprintf(stderr, "Error: Failed to generate password\n");
            database_free(&db);
            secure_zero(master_password, sizeof(master_password));
            return EXIT_FAILURE;
        }
        password_arg = password_buf;
        if (show_generated) {
            printf("Generated password: %s\n", password_arg);
        }
    } else {
        if (read_password("Password for entry: ", password_buf, 
                         sizeof(password_buf)) != PWM_SUCCESS) {
            fprintf(stderr, "Error: Failed to read password\n");
            database_free(&db);
            secure_zero(master_password, sizeof(master_password));
            return EXIT_FAILURE;
        }
        password_arg = password_buf;
    }
    
    // Create entry
    PasswordEntry entry;
    result = entry_create(&entry, domain, username, password_arg, comment);
    secure_zero(password_buf, sizeof(password_buf));
    
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, "Failed to create entry");
        database_free(&db);
        secure_zero(master_password, sizeof(master_password));
        return EXIT_FAILURE;
    }
    
    // Add to database
    result = database_add_entry(&db, &entry);
    entry_clear(&entry);
    
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, "Failed to add entry");
        database_free(&db);
        secure_zero(master_password, sizeof(master_password));
        return EXIT_FAILURE;
    }
    
    // Save database
    result = database_save(&db, master_password);
    secure_zero(master_password, sizeof(master_password));
    database_free(&db);
    
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, "Failed to save database");
        return EXIT_FAILURE;
    }
    
    printf("Entry added successfully\n");
    return EXIT_SUCCESS;
}


static int cmd_list(const char *db_path) {
    char master_password[MAX_MASTER_PASSWORD_LEN + 1];
    if (get_master_password(master_password, sizeof(master_password), 
                           "Master password: ") != PWM_SUCCESS) {
        fprintf(stderr, "Error: Failed to read password\n");
        return EXIT_FAILURE;
    }
    
    Database db;
    database_init(&db, db_path);
    
    int result = database_load(&db, db_path, master_password);
    secure_zero(master_password, sizeof(master_password));
    
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, "Failed to load database");
        return EXIT_FAILURE;
    }
    
    list_entries(&db);
    database_free(&db);
    
    return EXIT_SUCCESS;
}

static int cmd_get(const char *db_path, const char *query, bool password_only) {
    char master_password[MAX_MASTER_PASSWORD_LEN + 1];
    if (get_master_password(master_password, sizeof(master_password), 
                           "Master password: ") != PWM_SUCCESS) {
        fprintf(stderr, "Error: Failed to read password\n");
        return EXIT_FAILURE;
    }
    
    Database db;
    database_init(&db, db_path);
    
    int result = database_load(&db, db_path, master_password);
    secure_zero(master_password, sizeof(master_password));
    
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, "Failed to load database");
        return EXIT_FAILURE;
    }
    
    PasswordEntry entry;
    
    // Try as index first
    char *endptr;
    long index = strtol(query, &endptr, 10);
    
    if (*endptr == '\0' && index >= 0) {
        result = database_get_entry(&db, (size_t)index, &entry);
        if (result == PWM_SUCCESS) {
            if (password_only) {
                print_password_only(&entry);
            } else {
                display_entry(&entry, index);
            }
            entry_clear(&entry);
        }
    } else {
        char domain[MAX_DOMAIN_LEN + 1];
        char *username = NULL;
        
        result = parse_query(query, domain, &username);
        if (result != PWM_SUCCESS) {
            pwm_print_error(result, "Failed to parse query");
            database_free(&db);
            return EXIT_FAILURE;
        }
        
        result = database_find_entry(&db, domain, username, &entry);
        if (username) free(username);
        
        if (result == PWM_SUCCESS) {
            if (password_only) {
                print_password_only(&entry);
            } else {
                display_entry(&entry, -1);
            }
            entry_clear(&entry);
        }
    }
    
    database_free(&db);
    
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, NULL);
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

static int cmd_remove(const char *db_path, const char *query) {
    char master_password[MAX_MASTER_PASSWORD_LEN + 1];
    if (get_master_password(master_password, sizeof(master_password), 
                           "Master password: ") != PWM_SUCCESS) {
        fprintf(stderr, "Error: Failed to read password\n");
        return EXIT_FAILURE;
    }
    
    Database db;
    database_init(&db, db_path);
    
    int result = database_load(&db, db_path, master_password);
    
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, "Failed to load database");
        secure_zero(master_password, sizeof(master_password));
        return EXIT_FAILURE;
    }
    
    // Try as index first
    char *endptr;
    long index = strtol(query, &endptr, 10);
    
    if (*endptr == '\0' && index >= 0) {
        if (!confirm_action("Are you sure you want to remove this entry?")) {
            printf("Cancelled\n");
            database_free(&db);
            secure_zero(master_password, sizeof(master_password));
            return EXIT_SUCCESS;
        }
        
        result = database_remove_entry(&db, (size_t)index);
    } else {
        char domain[MAX_DOMAIN_LEN + 1];
        char *username = NULL;
        
        result = parse_query(query, domain, &username);
        if (result != PWM_SUCCESS) {
            pwm_print_error(result, "Failed to parse query");
            database_free(&db);
            secure_zero(master_password, sizeof(master_password));
            return EXIT_FAILURE;
        }
        
        if (!confirm_action("Are you sure you want to remove this entry?")) {
            printf("Cancelled\n");
            if (username) free(username);
            database_free(&db);
            secure_zero(master_password, sizeof(master_password));
            return EXIT_SUCCESS;
        }
        
        result = database_remove_entry_by_query(&db, domain, username);
        if (username) free(username);
    }
    
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, "Failed to remove entry");
        database_free(&db);
        secure_zero(master_password, sizeof(master_password));
        return EXIT_FAILURE;
    }
    
    // Save database
    result = database_save(&db, master_password);
    secure_zero(master_password, sizeof(master_password));
    database_free(&db);
    
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, "Failed to save database");
        return EXIT_FAILURE;
    }
    
    printf("Entry removed successfully\n");
    return EXIT_SUCCESS;
}

static int cmd_change_password(const char *db_path) {
    char old_password[MAX_MASTER_PASSWORD_LEN + 1];
    char new_password[MAX_MASTER_PASSWORD_LEN + 1];
    char confirm_password[MAX_MASTER_PASSWORD_LEN + 1];
    
    if (read_password("Current master password: ", old_password, 
                      sizeof(old_password)) != PWM_SUCCESS) {
        fprintf(stderr, "Error: Failed to read password\n");
        return EXIT_FAILURE;
    }
    
    Database db;
    database_init(&db, db_path);
    
    int result = database_load(&db, db_path, old_password);
    
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, "Failed to load database (wrong password?)");
        secure_zero(old_password, sizeof(old_password));
        return EXIT_FAILURE;
    }
    
    if (read_password("New master password: ", new_password, 
                      sizeof(new_password)) != PWM_SUCCESS) {
        fprintf(stderr, "Error: Failed to read password\n");
        database_free(&db);
        secure_zero(old_password, sizeof(old_password));
        return EXIT_FAILURE;
    }
    
    if (validate_master_password(new_password, ENFORCE_MASTER_PASSWORD_MIN) != PWM_SUCCESS) {
        database_free(&db);
        secure_zero(old_password, sizeof(old_password));
        secure_zero(new_password, sizeof(new_password));
        return EXIT_FAILURE;
    }
    
    if (read_password("Confirm new master password: ", confirm_password, 
                      sizeof(confirm_password)) != PWM_SUCCESS) {
        fprintf(stderr, "Error: Failed to read password\n");
        database_free(&db);
        secure_zero(old_password, sizeof(old_password));
        secure_zero(new_password, sizeof(new_password));
        return EXIT_FAILURE;
    }
    
    if (strcmp(new_password, confirm_password) != 0) {
        fprintf(stderr, "Error: Passwords do not match\n");
        database_free(&db);
        secure_zero(old_password, sizeof(old_password));
        secure_zero(new_password, sizeof(new_password));
        secure_zero(confirm_password, sizeof(confirm_password));
        return EXIT_FAILURE;
    }
    
    secure_zero(confirm_password, sizeof(confirm_password));
    
    result = database_change_password(&db, old_password, new_password);
    
    secure_zero(old_password, sizeof(old_password));
    secure_zero(new_password, sizeof(new_password));
    database_free(&db);
    
    if (result != PWM_SUCCESS) {
        pwm_print_error(result, "Failed to change password");
        return EXIT_FAILURE;
    }
    
    printf("Master password changed successfully\n");
    return EXIT_SUCCESS;
}

