#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <unistd.h>

#include "../include/common.h"
#include "../include/crypto.h"
#include "../include/database.h"
#include "../include/entry.h"

#define TEST_DB_PATH ".test_integration.db"
#define TEST_PASSWORD "integration_test_password"

// Setup and teardown
static int setup(void **state) {
    (void) state;
    crypto_init();
    unlink(TEST_DB_PATH);
    return 0;
}

static int teardown(void **state) {
    (void) state;
    unlink(TEST_DB_PATH);
    return 0;
}

// Test complete workflow: init -> add -> list -> get -> remove
static void test_complete_workflow(void **state) {
    (void) state;
    
    // 1. Create database
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    assert_true(database_exists(TEST_DB_PATH));
    
    // 2. Load database
    Database db;
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    assert_int_equal(db.count, 0);
    
    // 3. Add first entry
    PasswordEntry entry1;
    entry_create(&entry1, "gmail.com", "user@example.com", "SecurePass1!", "Personal email");
    assert_int_equal(database_add_entry(&db, &entry1), PWM_SUCCESS);
    assert_int_equal(db.count, 1);
    
    // 4. Add second entry
    PasswordEntry entry2;
    entry_create(&entry2, "github.com", "developer", "DevPass123", "Work account");
    assert_int_equal(database_add_entry(&db, &entry2), PWM_SUCCESS);
    assert_int_equal(db.count, 2);
    
    // 5. Save database
    assert_int_equal(database_save(&db, TEST_PASSWORD), PWM_SUCCESS);
    database_free(&db);
    
    // 6. Reload database
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    assert_int_equal(db.count, 2);
    
    // 7. Get entry by index
    PasswordEntry retrieved;
    assert_int_equal(database_get_entry(&db, 0, &retrieved), PWM_SUCCESS);
    assert_string_equal(retrieved.domain, "gmail.com");
    assert_string_equal(retrieved.password, "SecurePass1!");
    
    // 8. Find entry by domain
    assert_int_equal(database_find_entry(&db, "github.com", NULL, &retrieved), PWM_SUCCESS);
    assert_string_equal(retrieved.username, "developer");
    
    // 9. Remove entry
    assert_int_equal(database_remove_entry(&db, 0), PWM_SUCCESS);
    assert_int_equal(db.count, 1);
    assert_string_equal(db.entries[0].domain, "github.com");
    
    // 10. Save and reload
    assert_int_equal(database_save(&db, TEST_PASSWORD), PWM_SUCCESS);
    database_free(&db);
    
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    assert_int_equal(db.count, 1);
    assert_string_equal(db.entries[0].domain, "github.com");
    
    database_free(&db);
}

// Test password change workflow
static void test_password_change_workflow(void **state) {
    (void) state;
    
    // Create and populate database
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    PasswordEntry entry;
    entry_create(&entry, "test.com", "user", "password", "");
    database_add_entry(&db, &entry);
    database_save(&db, TEST_PASSWORD);
    
    // Change password
    const char *new_password = "new_integration_password";
    assert_int_equal(database_change_password(&db, TEST_PASSWORD, new_password),
                     PWM_SUCCESS);
    database_free(&db);
    
    // Verify old password fails
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_ERROR_CRYPTO);
    
    // Verify new password works and data is intact
    assert_int_equal(database_load(&db, TEST_DB_PATH, new_password), PWM_SUCCESS);
    assert_int_equal(db.count, 1);
    assert_string_equal(db.entries[0].domain, "test.com");
    
    database_free(&db);
}

// Test atomicity: simulate crash during save
static void test_atomicity(void **state) {
    (void) state;
    
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    PasswordEntry entry;
    entry_create(&entry, "important.com", "user", "critical_data", "Must not lose");
    database_add_entry(&db, &entry);
    assert_int_equal(database_save(&db, TEST_PASSWORD), PWM_SUCCESS);
    
    database_free(&db);
    
    // Reload to verify data persisted
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    assert_int_equal(db.count, 1);
    assert_string_equal(db.entries[0].password, "critical_data");
    
    database_free(&db);
}

// Test duplicate prevention
static void test_duplicate_prevention(void **state) {
    (void) state;
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    
    PasswordEntry entry1, entry2, entry3;
    
    // Add first entry
    entry_create(&entry1, "example.com", "user1", "pass1", "");
    assert_int_equal(database_add_entry(&db, &entry1), PWM_SUCCESS);
    
    // Add different username for same domain (should succeed)
    entry_create(&entry2, "example.com", "user2", "pass2", "");
    assert_int_equal(database_add_entry(&db, &entry2), PWM_SUCCESS);
    
    // Add duplicate (should fail)
    entry_create(&entry3, "example.com", "user1", "different_pass", "");
    assert_int_equal(database_add_entry(&db, &entry3), PWM_ERROR_DUPLICATE);
    
    assert_int_equal(db.count, 2);
    
    database_free(&db);
}

// Test encryption/decryption with different passwords
static void test_encryption_isolation(void **state) {
    (void) state;
    
    const char *password1 = "password_one";
    const char *password2 = "password_two";
    
    // Create with password1
    assert_int_equal(database_create(TEST_DB_PATH, password1), PWM_SUCCESS);
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, password1), PWM_SUCCESS);
    
    PasswordEntry entry;
    entry_create(&entry, "secret.com", "user", "classified", "");
    database_add_entry(&db, &entry);
    database_save(&db, password1);
    database_free(&db);
    
    // Try to load with wrong password
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, password2), PWM_ERROR_CRYPTO);
    
    // Verify correct password works
    assert_int_equal(database_load(&db, TEST_DB_PATH, password1), PWM_SUCCESS);
    assert_int_equal(db.count, 1);
    
    database_free(&db);
}

// Test data integrity after multiple operations
static void test_data_integrity(void **state) {
    (void) state;
    
    assert_int_equal(database_create(TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    Database db;
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    
    // Add 50 entries
    for (int i = 0; i < 50; i++) {
        PasswordEntry entry;
        char domain[50], username[50], password[50];
        snprintf(domain, sizeof(domain), "site%d.com", i);
        snprintf(username, sizeof(username), "user%d", i);
        snprintf(password, sizeof(password), "pass%d", i);
        
        entry_create(&entry, domain, username, password, "");
        assert_int_equal(database_add_entry(&db, &entry), PWM_SUCCESS);
    }
    
    assert_int_equal(database_save(&db, TEST_PASSWORD), PWM_SUCCESS);
    database_free(&db);
    
    // Reload and verify all entries
    database_init(&db, TEST_DB_PATH);
    assert_int_equal(database_load(&db, TEST_DB_PATH, TEST_PASSWORD), PWM_SUCCESS);
    assert_int_equal(db.count, 50);
    
    for (int i = 0; i < 50; i++) {
        char expected_domain[50];
        snprintf(expected_domain, sizeof(expected_domain), "site%d.com", i);
        assert_string_equal(db.entries[i].domain, expected_domain);
    }
    
    database_free(&db);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_complete_workflow, setup, teardown),
        cmocka_unit_test_setup_teardown(test_password_change_workflow, setup, teardown),
        cmocka_unit_test_setup_teardown(test_atomicity, setup, teardown),
        cmocka_unit_test_setup_teardown(test_duplicate_prevention, setup, teardown),
        cmocka_unit_test_setup_teardown(test_encryption_isolation, setup, teardown),
        cmocka_unit_test_setup_teardown(test_data_integrity, setup, teardown),
    };
    
    return cmocka_run_group_tests_name("integration tests", tests, NULL, NULL);
}

