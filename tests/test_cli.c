#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

#include "../include/cli.h"
#include "../include/crypto.h"

// Test parse_query
static void test_parse_query_domain_only(void **state) {
    (void) state;
    char domain[MAX_DOMAIN_LEN + 1];
    char *username = NULL;
    
    assert_int_equal(parse_query("example.com", domain, &username), PWM_SUCCESS);
    assert_string_equal(domain, "example.com");
    assert_null(username);
}

static void test_parse_query_domain_and_username(void **state) {
    (void) state;
    char domain[MAX_DOMAIN_LEN + 1];
    char *username = NULL;
    
    assert_int_equal(parse_query("example.com:user@test.com", domain, &username),
                     PWM_SUCCESS);
    assert_string_equal(domain, "example.com");
    assert_non_null(username);
    assert_string_equal(username, "user@test.com");
    
    free(username);
}

static void test_parse_query_empty_domain(void **state) {
    (void) state;
    char domain[MAX_DOMAIN_LEN + 1];
    char *username = NULL;
    
    assert_int_equal(parse_query(":username", domain, &username),
                     PWM_ERROR_INVALID_INPUT);
}

static void test_parse_query_empty_username(void **state) {
    (void) state;
    char domain[MAX_DOMAIN_LEN + 1];
    char *username = NULL;
    
    assert_int_equal(parse_query("domain:", domain, &username),
                     PWM_ERROR_INVALID_INPUT);
}

static void test_parse_query_null_parameters(void **state) {
    (void) state;
    char domain[MAX_DOMAIN_LEN + 1];
    char *username = NULL;
    
    assert_int_equal(parse_query(NULL, domain, &username), PWM_ERROR_INVALID_INPUT);
    assert_int_equal(parse_query("test", NULL, &username), PWM_ERROR_INVALID_INPUT);
    assert_int_equal(parse_query("test", domain, NULL), PWM_ERROR_INVALID_INPUT);
}

static void test_parse_query_with_control_chars(void **state) {
    (void) state;
    char domain[MAX_DOMAIN_LEN + 1];
    char *username = NULL;
    
    assert_int_equal(parse_query("test\ntest", domain, &username),
                     PWM_ERROR_INVALID_INPUT);
    assert_int_equal(parse_query("test:user\ntest", domain, &username),
                     PWM_ERROR_INVALID_INPUT);
}

static void test_parse_query_too_long(void **state) {
    (void) state;
    char domain[MAX_DOMAIN_LEN + 1];
    char *username = NULL;
    char long_query[MAX_DOMAIN_LEN + 100];
    
    memset(long_query, 'A', MAX_DOMAIN_LEN + 50);
    long_query[MAX_DOMAIN_LEN + 50] = '\0';
    
    assert_int_equal(parse_query(long_query, domain, &username),
                     PWM_ERROR_INVALID_INPUT);
}

// Test list_entries
static void test_list_entries_empty_database(void **state) {
    (void) state;
    Database db;
    database_init(&db, "test.db");
    
    // Should not crash
    list_entries(&db);
    
    database_free(&db);
}

static void test_list_entries_with_entries(void **state) {
    (void) state;
    Database db;
    database_init(&db, "test.db");
    
    PasswordEntry entry;
    entry_create(&entry, "gmail.com", "user@example.com", "password", "2FA enabled");
    database_add_entry(&db, &entry);
    
    // Should not crash and should display entry (visual inspection needed)
    list_entries(&db);
    
    database_free(&db);
}

// Test display_entry
static void test_display_entry_with_index(void **state) {
    (void) state;
    PasswordEntry entry;
    entry_create(&entry, "example.com", "user", "SecretPass", "My comment");
    
    // Should not crash
    display_entry(&entry, 0);
    entry_clear(&entry);
}

static void test_display_entry_without_index(void **state) {
    (void) state;
    PasswordEntry entry;
    entry_create(&entry, "example.com", "user", "SecretPass", "");
    
    // Should not crash
    display_entry(&entry, -1);
    entry_clear(&entry);
}

static void test_display_entry_null(void **state) {
    (void) state;
    // Should not crash
    display_entry(NULL, 0);
}

// Test pwm_print_error
static void test_pwm_print_error_all_codes(void **state) {
    (void) state;
    
    // Should not crash for any error code
    pwm_print_error(PWM_ERROR_INVALID_INPUT, "test");
    pwm_print_error(PWM_ERROR_NOT_FOUND, "test");
    pwm_print_error(PWM_ERROR_DUPLICATE, "test");
    pwm_print_error(PWM_ERROR_CRYPTO, "test");
    pwm_print_error(PWM_ERROR_FILE, "test");
    pwm_print_error(PWM_ERROR_PERMISSION, "test");
    pwm_print_error(PWM_ERROR_MEMORY, "test");
    pwm_print_error(PWM_ERROR, "test");
    pwm_print_error(999, "test");
}

static void test_pwm_print_error_null_message(void **state) {
    (void) state;
    // Should not crash
    pwm_print_error(PWM_ERROR_INVALID_INPUT, NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_query_domain_only),
        cmocka_unit_test(test_parse_query_domain_and_username),
        cmocka_unit_test(test_parse_query_empty_domain),
        cmocka_unit_test(test_parse_query_empty_username),
        cmocka_unit_test(test_parse_query_null_parameters),
        cmocka_unit_test(test_parse_query_with_control_chars),
        cmocka_unit_test(test_parse_query_too_long),
        
        cmocka_unit_test(test_list_entries_empty_database),
        cmocka_unit_test(test_list_entries_with_entries),
        
        cmocka_unit_test(test_display_entry_with_index),
        cmocka_unit_test(test_display_entry_without_index),
        cmocka_unit_test(test_display_entry_null),
        
        cmocka_unit_test(test_pwm_print_error_all_codes),
        cmocka_unit_test(test_pwm_print_error_null_message),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}

