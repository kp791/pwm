#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

#include "../include/entry.h"
#include "../include/crypto.h"

// Test validate_string
static void test_validate_string_null(void **state) {
    (void) state;
    assert_int_equal(validate_string(NULL, 100, false), PWM_ERROR_INVALID_INPUT);
}

static void test_validate_string_empty(void **state) {
    (void) state;
    assert_int_equal(validate_string("", 100, false), PWM_ERROR_INVALID_INPUT);
    assert_int_equal(validate_string("", 100, true), PWM_SUCCESS);
}

static void test_validate_string_too_long(void **state) {
    (void) state;
    char long_string[300];
    memset(long_string, 'A', 299);
    long_string[299] = '\0';
    
    assert_int_equal(validate_string(long_string, 100, false), PWM_ERROR_INVALID_INPUT);
}

static void test_validate_string_control_chars(void **state) {
    (void) state;
    assert_int_equal(validate_string("test\ntest", 100, false), PWM_ERROR_INVALID_INPUT);
    // REMOVED: assert_int_equal(validate_string("test\x00test", 100, false), PWM_ERROR_INVALID_INPUT);
    // C strings terminate at \0, so this test doesn't make sense
    assert_int_equal(validate_string("test\ttest", 100, false), PWM_ERROR_INVALID_INPUT);
    assert_int_equal(validate_string("test\x1Ftest", 100, false), PWM_ERROR_INVALID_INPUT);
    assert_int_equal(validate_string("test\x7Ftest", 100, false), PWM_ERROR_INVALID_INPUT);
    
    // Additional test: string starting with null should be rejected as empty
    assert_int_equal(validate_string("", 100, false), PWM_ERROR_INVALID_INPUT);
}

static void test_validate_string_valid(void **state) {
    (void) state;
    assert_int_equal(validate_string("valid_string_123", 100, false), PWM_SUCCESS);
    assert_int_equal(validate_string("Valid String!", 100, false), PWM_SUCCESS);
    assert_int_equal(validate_string("email@example.com", 100, false), PWM_SUCCESS);
}

// Test entry_create
static void test_entry_create_null_parameters(void **state) {
    (void) state;
    PasswordEntry entry;
    
    assert_int_equal(entry_create(NULL, "domain", "user", "pass", NULL),
                     PWM_ERROR_INVALID_INPUT);
    assert_int_equal(entry_create(&entry, NULL, "user", "pass", NULL),
                     PWM_ERROR_INVALID_INPUT);
    assert_int_equal(entry_create(&entry, "domain", NULL, "pass", NULL),
                     PWM_ERROR_INVALID_INPUT);
    assert_int_equal(entry_create(&entry, "domain", "user", NULL, NULL),
                     PWM_ERROR_INVALID_INPUT);
}

static void test_entry_create_invalid_fields(void **state) {
    (void) state;
    PasswordEntry entry;
    
    assert_int_equal(entry_create(&entry, "", "user", "pass", NULL),
                     PWM_ERROR_INVALID_INPUT);
    assert_int_equal(entry_create(&entry, "domain", "", "pass", NULL),
                     PWM_ERROR_INVALID_INPUT);
    assert_int_equal(entry_create(&entry, "domain", "user", "", NULL),
                     PWM_ERROR_INVALID_INPUT);
    assert_int_equal(entry_create(&entry, "test\ntest", "user", "pass", NULL),
                     PWM_ERROR_INVALID_INPUT);
}

static void test_entry_create_valid(void **state) {
    (void) state;
    PasswordEntry entry;
    
    assert_int_equal(entry_create(&entry, "gmail.com", "user@example.com",
                                  "SecurePass123!", "My comment"),
                     PWM_SUCCESS);
    
    assert_string_equal(entry.domain, "gmail.com");
    assert_string_equal(entry.username, "user@example.com");
    assert_string_equal(entry.password, "SecurePass123!");
    assert_string_equal(entry.comment, "My comment");
}

static void test_entry_create_no_comment(void **state) {
    (void) state;
    PasswordEntry entry;
    
    assert_int_equal(entry_create(&entry, "github.com", "developer",
                                  "password", NULL),
                     PWM_SUCCESS);
    
    assert_string_equal(entry.domain, "github.com");
    assert_string_equal(entry.username, "developer");
    assert_string_equal(entry.password, "password");
    assert_string_equal(entry.comment, "");
}

static void test_entry_create_field_length_limits(void **state) {
    (void) state;
    PasswordEntry entry;
    char long_domain[MAX_DOMAIN_LEN + 10];
    
    memset(long_domain, 'A', MAX_DOMAIN_LEN + 5);
    long_domain[MAX_DOMAIN_LEN + 5] = '\0';
    
    assert_int_equal(entry_create(&entry, long_domain, "user", "pass", NULL),
                     PWM_ERROR_INVALID_INPUT);
}

// Test entry_validate
static void test_entry_validate_null(void **state) {
    (void) state;
    assert_int_equal(entry_validate(NULL), PWM_ERROR_INVALID_INPUT);
}

static void test_entry_validate_valid(void **state) {
    (void) state;
    PasswordEntry entry;
    
    entry_create(&entry, "example.com", "user", "password", "comment");
    assert_int_equal(entry_validate(&entry), PWM_SUCCESS);
}

static void test_entry_validate_invalid(void **state) {
    (void) state;
    PasswordEntry entry;
    
    entry_create(&entry, "example.com", "user", "password", "comment");
    
    // Corrupt the entry
    entry.domain[0] = '\n';
    assert_int_equal(entry_validate(&entry), PWM_ERROR_INVALID_INPUT);
}

// Test entry_matches
static void test_entry_matches_same(void **state) {
    (void) state;
    PasswordEntry entry1, entry2;
    
    entry_create(&entry1, "gmail.com", "user@example.com", "pass1", "comment1");
    entry_create(&entry2, "gmail.com", "user@example.com", "pass2", "comment2");
    
    assert_true(entry_matches(&entry1, &entry2));
}

static void test_entry_matches_different_domain(void **state) {
    (void) state;
    PasswordEntry entry1, entry2;
    
    entry_create(&entry1, "gmail.com", "user@example.com", "pass", "");
    entry_create(&entry2, "github.com", "user@example.com", "pass", "");
    
    assert_false(entry_matches(&entry1, &entry2));
}

static void test_entry_matches_different_username(void **state) {
    (void) state;
    PasswordEntry entry1, entry2;
    
    entry_create(&entry1, "gmail.com", "user1@example.com", "pass", "");
    entry_create(&entry2, "gmail.com", "user2@example.com", "pass", "");
    
    assert_false(entry_matches(&entry1, &entry2));
}

static void test_entry_matches_null(void **state) {
    (void) state;
    PasswordEntry entry;
    
    entry_create(&entry, "gmail.com", "user", "pass", "");
    
    assert_false(entry_matches(NULL, &entry));
    assert_false(entry_matches(&entry, NULL));
    assert_false(entry_matches(NULL, NULL));
}

// Test entry_matches_query
static void test_entry_matches_query_domain_only(void **state) {
    (void) state;
    PasswordEntry entry;
    
    entry_create(&entry, "gmail.com", "user@example.com", "pass", "");
    
    assert_true(entry_matches_query(&entry, "gmail.com", NULL));
    assert_false(entry_matches_query(&entry, "github.com", NULL));
}

static void test_entry_matches_query_domain_and_username(void **state) {
    (void) state;
    PasswordEntry entry;
    
    entry_create(&entry, "gmail.com", "user@example.com", "pass", "");
    
    assert_true(entry_matches_query(&entry, "gmail.com", "user@example.com"));
    assert_false(entry_matches_query(&entry, "gmail.com", "other@example.com"));
    assert_false(entry_matches_query(&entry, "github.com", "user@example.com"));
}

static void test_entry_matches_query_null(void **state) {
    (void) state;
    PasswordEntry entry;
    
    entry_create(&entry, "gmail.com", "user", "pass", "");
    
    assert_false(entry_matches_query(NULL, "gmail.com", NULL));
    assert_false(entry_matches_query(&entry, NULL, NULL));
}

// Test entry_clear
static void test_entry_clear_zeros_password(void **state) {
    (void) state;
    PasswordEntry entry;
    
    entry_create(&entry, "gmail.com", "user", "SecretPassword", "comment");
    
    entry_clear(&entry);
    
    // Password should be zeroed
    for (size_t i = 0; i < sizeof(entry.password); i++) {
        assert_int_equal(entry.password[i], 0);
    }
}

static void test_entry_clear_null(void **state) {
    (void) state;
    // Should not crash
    entry_clear(NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_validate_string_null),
        cmocka_unit_test(test_validate_string_empty),
        cmocka_unit_test(test_validate_string_too_long),
        cmocka_unit_test(test_validate_string_control_chars),
        cmocka_unit_test(test_validate_string_valid),
        
        cmocka_unit_test(test_entry_create_null_parameters),
        cmocka_unit_test(test_entry_create_invalid_fields),
        cmocka_unit_test(test_entry_create_valid),
        cmocka_unit_test(test_entry_create_no_comment),
        cmocka_unit_test(test_entry_create_field_length_limits),
        
        cmocka_unit_test(test_entry_validate_null),
        cmocka_unit_test(test_entry_validate_valid),
        cmocka_unit_test(test_entry_validate_invalid),
        
        cmocka_unit_test(test_entry_matches_same),
        cmocka_unit_test(test_entry_matches_different_domain),
        cmocka_unit_test(test_entry_matches_different_username),
        cmocka_unit_test(test_entry_matches_null),
        
        cmocka_unit_test(test_entry_matches_query_domain_only),
        cmocka_unit_test(test_entry_matches_query_domain_and_username),
        cmocka_unit_test(test_entry_matches_query_null),
        
        cmocka_unit_test(test_entry_clear_zeros_password),
        cmocka_unit_test(test_entry_clear_null),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}

