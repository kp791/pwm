#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../include/database.h"
#include "../include/crypto.h"

#define TEST_DB_PATH ".test_pwm.db"
#define TEST_PASSWORD "test_master_password"

// Setup and teardown functions
static int setup_crypto(void **state) {
    (void) state;
    return crypto_init();
}

static int teardown_test_db(void **state) {
    (void) state;
    unlink(TEST_DB_PATH);
    return 0;
}

// Test database_init
static void test_database_init(void **state) {
    (void) state;
    Database db;
    
    database_init(&db, TEST_DB_PATH);
    
    assert_null(db.entries);
    assert_int_equal(db.count, 0);
    assert_int_equal(db.capacity, 0);
    assert_string_equal(db.path, TEST_DB_PATH);
}

// Test database_exists
static void test_database_exists_no_file(void **state) {
    (void) state;
    unlink(TEST_DB_PATH);
    assert_false(database_exists(TEST_DB_PATH));
}

static void test_database_exists_file_present(void **state) {
    (void) state;
    
    // Create test database
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    assert_true(database_exists(TEST_DB_PATH));
}

// Test database_create
static void test_database_create_success(void **state) {
    (void) state;
    
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    assert_true(database_exists(TEST_DB_PATH));
    
    // Check permissions
    struct stat st;
    assert_int_equal(stat(TEST_DB_PATH, &st), 0);
    assert_int_equal(st.st_mode & 0777, 0600);
}

static void test_database_create_already_exists(void **state) {
    (void) state;
    
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_ERROR_FILE);
}

static void test_database_create_invalid_password(void **state) {
    (void) state;
    
    assert_int_equal(database_create(TEST_DB_PATH, "pass\nword"), PWM_ERROR_INVALID_INPUT);
}

// Test database_load
static void test_database_load_success(void **state) {
    (void) state;
    
    // Create database first
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    // Load it
    Database db;
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    assert_int_equal(db.count, 0);
    assert_string_equal(db.path, TEST_DB_PATH);
    
    database_free(&db);
}

static void test_database_load_wrong_password(void **state) {
    (void) state;
    
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, "wrong_password"), PWM_ERROR_CRYPTO);
}

static void test_database_load_nonexistent(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, "nonexistent.db");
    assert_int_not_equal(database_load(&db, "nonexistent.db", TEST_PASSWORD), PWM_SUCCESS);
}

// Test database_save
static void test_database_save_success(void **state) {
    (void) state;
    
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    // Add an entry
    PasswordEntry entry;
    entry_create(&entry, "example.com", "user", "password", "comment");
    assert_int_equal(database_add_entry(&db, &entry), PWM_SUCCESS);
    
    // Save
    assert_int_equal(database_save(&db, TEST_PASSWORD), PWM_SUCCESS);
    
    database_free(&db);
    
    // Reload and verify
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    assert_int_equal(db.count, 1);
    assert_string_equal(db.entries[0].domain, "example.com");
    
    database_free(&db);
}

// Test database_add_entry
static void test_database_add_entry_success(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    PasswordEntry entry;
    entry_create(&entry, "gmail.com", "user@example.com", "password123", "2FA");
    
    assert_int_equal(database_add_entry(&db, &entry), PWM_SUCCESS);
    assert_int_equal(db.count, 1);
    assert_string_equal(db.entries[0].domain, "gmail.com");
    
    database_free(&db);
}

static void test_database_add_entry_duplicate(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    PasswordEntry entry1, entry2;
    entry_create(&entry1, "gmail.com", "user", "pass1", "");
    entry_create(&entry2, "gmail.com", "user", "pass2", "");
    
    assert_int_equal(database_add_entry(&db, &entry1), PWM_SUCCESS);
    assert_int_equal(database_add_entry(&db, &entry2), PWM_ERROR_DUPLICATE);
    
    database_free(&db);
}

static void test_database_add_entry_multiple(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    for (int i = 0; i < 10; i++) {
        PasswordEntry entry;
        char domain[50];
        snprintf(domain, sizeof(domain), "site%d.com", i);
        entry_create(&entry, domain, "user", "pass", "");
        assert_int_equal(database_add_entry(&db, &entry), PWM_SUCCESS);
    }
    
    assert_int_equal(db.count, 10);
    
    database_free(&db);
}

// Test database_get_entry
static void test_database_get_entry_success(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    PasswordEntry entry;
    entry_create(&entry, "example.com", "user", "password", "comment");
    database_add_entry(&db, &entry);
    
    PasswordEntry retrieved;
    assert_int_equal(database_get_entry(&db, 0, &retrieved), PWM_SUCCESS);
    assert_string_equal(retrieved.domain, "example.com");
    assert_string_equal(retrieved.password, "password");
    
    database_free(&db);
}

static void test_database_get_entry_invalid_index(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    PasswordEntry entry;
    entry_create(&entry, "example.com", "user", "password", "");
    database_add_entry(&db, &entry);
    
    PasswordEntry retrieved;
    assert_int_equal(database_get_entry(&db, 1, &retrieved), PWM_ERROR_NOT_FOUND);
    assert_int_equal(database_get_entry(&db, 100, &retrieved), PWM_ERROR_NOT_FOUND);
    
    database_free(&db);
}

// Test database_find_entry
static void test_database_find_entry_by_domain(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    PasswordEntry entry1, entry2;
    entry_create(&entry1, "gmail.com", "user1", "pass1", "");
    entry_create(&entry2, "github.com", "user2", "pass2", "");
    database_add_entry(&db, &entry1);
    database_add_entry(&db, &entry2);
    
    PasswordEntry found;
    assert_int_equal(database_find_entry(&db, "github.com", NULL, &found), PWM_SUCCESS);
    assert_string_equal(found.domain, "github.com");
    assert_string_equal(found.username, "user2");
    
    database_free(&db);
}

static void test_database_find_entry_by_domain_and_username(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    PasswordEntry entry1, entry2;
    entry_create(&entry1, "gmail.com", "user1", "pass1", "");
    entry_create(&entry2, "gmail.com", "user2", "pass2", "");
    database_add_entry(&db, &entry1);
    database_add_entry(&db, &entry2);
    
    PasswordEntry found;
    assert_int_equal(database_find_entry(&db, "gmail.com", "user2", &found), PWM_SUCCESS);
    assert_string_equal(found.username, "user2");
    assert_string_equal(found.password, "pass2");
    
    database_free(&db);
}

static void test_database_find_entry_not_found(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    PasswordEntry entry;
    entry_create(&entry, "gmail.com", "user", "pass", "");
    database_add_entry(&db, &entry);
    
    PasswordEntry found;
    assert_int_equal(database_find_entry(&db, "nonexistent.com", NULL, &found),
                     PWM_ERROR_NOT_FOUND);
    
    database_free(&db);
}

// Test database_remove_entry
static void test_database_remove_entry_success(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    PasswordEntry entry1, entry2;
    entry_create(&entry1, "site1.com", "user1", "pass1", "");
    entry_create(&entry2, "site2.com", "user2", "pass2", "");
    database_add_entry(&db, &entry1);
    database_add_entry(&db, &entry2);
    
    assert_int_equal(db.count, 2);
    assert_int_equal(database_remove_entry(&db, 0), PWM_SUCCESS);
    assert_int_equal(db.count, 1);
    assert_string_equal(db.entries[0].domain, "site2.com");
    
    database_free(&db);
}

static void test_database_remove_entry_invalid_index(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    PasswordEntry entry;
    entry_create(&entry, "site.com", "user", "pass", "");
    database_add_entry(&db, &entry);
    
    assert_int_equal(database_remove_entry(&db, 5), PWM_ERROR_NOT_FOUND);
    
    database_free(&db);
}

// Test database_remove_entry_by_query
static void test_database_remove_entry_by_query_success(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    PasswordEntry entry;
    entry_create(&entry, "example.com", "user", "pass", "");
    database_add_entry(&db, &entry);
    
    assert_int_equal(database_remove_entry_by_query(&db, "example.com", NULL), PWM_SUCCESS);
    assert_int_equal(db.count, 0);
    
    database_free(&db);
}

// Test database_change_password
static void test_database_change_password_success(void **state) {
    (void) state;
    
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    // Add entry
    PasswordEntry entry;
    entry_create(&entry, "test.com", "user", "password", "");
    database_add_entry(&db, &entry);
    database_save(&db, TEST_PASSWORD);
    
    // Change password
    const char *new_password = "new_master_password";
    assert_int_equal(database_change_password(&db, TEST_PASSWORD, new_password), PWM_SUCCESS);
    
    database_free(&db);
    
    // Verify old password doesn't work
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_ERROR_CRYPTO);
    
    // Verify new password works
    assert_int_equal(database_load(&db, TEST_DB_PATH, new_password), PWM_SUCCESS);
    assert_int_equal(db.count, 1);
    
    database_free(&db);
}

// Test ensure_secure_permissions
static void test_ensure_secure_permissions_success(void **state) {
    (void) state;
    
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    // Change permissions to something else
    chmod(TEST_DB_PATH, 0644);
    
    // Ensure should fix it
    assert_int_equal(ensure_secure_permissions(TEST_DB_PATH), PWM_SUCCESS);
    
    struct stat st;
    assert_int_equal(stat(TEST_DB_PATH, &st), 0);
    assert_int_equal(st.st_mode & 0777, 0600);
}

// Test database_free
static void test_database_free_clears_passwords(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    PasswordEntry entry;
    entry_create(&entry, "test.com", "user", "SecretPassword", "");
    database_add_entry(&db, &entry);
    
    database_free(&db);
    
    assert_null(db.entries);
    assert_int_equal(db.count, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_database_init),
        
        cmocka_unit_test_teardown(test_database_exists_no_file, teardown_test_db),
        cmocka_unit_test_teardown(test_database_exists_file_present, teardown_test_db),
        
        cmocka_unit_test_teardown(test_database_create_success, teardown_test_db),
        cmocka_unit_test_teardown(test_database_create_already_exists, teardown_test_db),
        cmocka_unit_test_teardown(test_database_create_invalid_password, teardown_test_db),
        
        cmocka_unit_test_teardown(test_database_load_success, teardown_test_db),
        cmocka_unit_test_teardown(test_database_load_wrong_password, teardown_test_db),
        cmocka_unit_test_teardown(test_database_load_nonexistent, teardown_test_db),
        
        cmocka_unit_test_teardown(test_database_save_success, teardown_test_db),
        
        cmocka_unit_test(test_database_add_entry_success),
        cmocka_unit_test(test_database_add_entry_duplicate),
        cmocka_unit_test(test_database_add_entry_multiple),
        
        cmocka_unit_test(test_database_get_entry_success),
        cmocka_unit_test(test_database_get_entry_invalid_index),
        
        cmocka_unit_test(test_database_find_entry_by_domain),
        cmocka_unit_test(test_database_find_entry_by_domain_and_username),
        cmocka_unit_test(test_database_find_entry_not_found),
        
        cmocka_unit_test(test_database_remove_entry_success),
        cmocka_unit_test(test_database_remove_entry_invalid_index),
        cmocka_unit_test(test_database_remove_entry_by_query_success),
        
        cmocka_unit_test_teardown(test_database_change_password_success, teardown_test_db),
        cmocka_unit_test_teardown(test_ensure_secure_permissions_success, teardown_test_db),
        
        cmocka_unit_test(test_database_free_clears_passwords),
    };
    
    return cmocka_run_group_tests_name("database tests", tests, setup_crypto, NULL);
}

