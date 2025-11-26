#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <ctype.h>

#include "../include/crypto.h"

// Test crypto_init
static void test_crypto_init_success(void **state) {
    (void) state;
    assert_int_equal(crypto_init(), PWM_SUCCESS);
}

// Test derive_key
static void test_derive_key_null_parameters(void **state) {
    (void) state;
    unsigned char salt[SALT_BYTES] = {0};
    unsigned char key[KEY_BYTES] = {0};
    
    assert_int_equal(derive_key(NULL, salt, key), PWM_ERROR_INVALID_INPUT);
    assert_int_equal(derive_key("password", NULL, key), PWM_ERROR_INVALID_INPUT);
    assert_int_equal(derive_key("password", salt, NULL), PWM_ERROR_INVALID_INPUT);
}

static void test_derive_key_consistency(void **state) {
    (void) state;
    unsigned char salt[SALT_BYTES];
    unsigned char key1[KEY_BYTES];
    unsigned char key2[KEY_BYTES];
    
    generate_random_bytes(salt, SALT_BYTES);
    
    assert_int_equal(derive_key("test_password", salt, key1), PWM_SUCCESS);
    assert_int_equal(derive_key("test_password", salt, key2), PWM_SUCCESS);
    
    // Same password and salt should produce same key
    assert_memory_equal(key1, key2, KEY_BYTES);
}

static void test_derive_key_different_passwords(void **state) {
    (void) state;
    unsigned char salt[SALT_BYTES];
    unsigned char key1[KEY_BYTES];
    unsigned char key2[KEY_BYTES];
    
    generate_random_bytes(salt, SALT_BYTES);
    
    assert_int_equal(derive_key("password1", salt, key1), PWM_SUCCESS);
    assert_int_equal(derive_key("password2", salt, key2), PWM_SUCCESS);
    
    // Different passwords should produce different keys
    assert_memory_not_equal(key1, key2, KEY_BYTES);
}

static void test_derive_key_different_salts(void **state) {
    (void) state;
    unsigned char salt1[SALT_BYTES];
    unsigned char salt2[SALT_BYTES];
    unsigned char key1[KEY_BYTES];
    unsigned char key2[KEY_BYTES];
    
    generate_random_bytes(salt1, SALT_BYTES);
    generate_random_bytes(salt2, SALT_BYTES);
    
    assert_int_equal(derive_key("password", salt1, key1), PWM_SUCCESS);
    assert_int_equal(derive_key("password", salt2, key2), PWM_SUCCESS);
    
    // Different salts should produce different keys
    assert_memory_not_equal(key1, key2, KEY_BYTES);
}

// Test encrypt_data
static void test_encrypt_data_null_parameters(void **state) {
    (void) state;
    unsigned char key[KEY_BYTES] = {0};
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char nonce[NONCE_BYTES] = {0};
    
    generate_random_bytes(key, KEY_BYTES);
    
    assert_int_equal(encrypt_data(NULL, 10, key, &ciphertext, &ciphertext_len, nonce),
                     PWM_ERROR_INVALID_INPUT);
    assert_int_equal(encrypt_data((unsigned char*)"data", 4, NULL, &ciphertext, &ciphertext_len, nonce),
                     PWM_ERROR_INVALID_INPUT);
    assert_int_equal(encrypt_data((unsigned char*)"data", 4, key, NULL, &ciphertext_len, nonce),
                     PWM_ERROR_INVALID_INPUT);
}

static void test_encrypt_decrypt_roundtrip(void **state) {
    (void) state;
    const char *plaintext = "secret password data";
    unsigned char key[KEY_BYTES];
    unsigned char nonce[NONCE_BYTES];
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *decrypted;
    size_t decrypted_len;
    
    generate_random_bytes(key, KEY_BYTES);
    
    // Encrypt
    assert_int_equal(encrypt_data((const unsigned char*)plaintext, strlen(plaintext),
                                  key, &ciphertext, &ciphertext_len, nonce),
                     PWM_SUCCESS);
    
    assert_non_null(ciphertext);
    assert_true(ciphertext_len > strlen(plaintext)); // Should include MAC
    
    // Decrypt
    assert_int_equal(decrypt_data(ciphertext, ciphertext_len, key, nonce,
                                  &decrypted, &decrypted_len),
                     PWM_SUCCESS);
    
    assert_non_null(decrypted);
    assert_int_equal(decrypted_len, strlen(plaintext));
    assert_memory_equal(plaintext, decrypted, strlen(plaintext));
    
    sodium_free(ciphertext);
    sodium_free(decrypted);
}

static void test_decrypt_wrong_key(void **state) {
    (void) state;
    const char *plaintext = "secret data";
    unsigned char key1[KEY_BYTES];
    unsigned char key2[KEY_BYTES];
    unsigned char nonce[NONCE_BYTES];
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *decrypted;
    size_t decrypted_len;
    
    generate_random_bytes(key1, KEY_BYTES);
    generate_random_bytes(key2, KEY_BYTES);
    
    // Encrypt with key1
    assert_int_equal(encrypt_data((const unsigned char*)plaintext, strlen(plaintext),
                                  key1, &ciphertext, &ciphertext_len, nonce),
                     PWM_SUCCESS);
    
    // Try to decrypt with key2 (should fail)
    assert_int_equal(decrypt_data(ciphertext, ciphertext_len, key2, nonce,
                                  &decrypted, &decrypted_len),
                     PWM_ERROR_CRYPTO);
    
    sodium_free(ciphertext);
}

static void test_decrypt_tampered_data(void **state) {
    (void) state;
    const char *plaintext = "secret data";
    unsigned char key[KEY_BYTES];
    unsigned char nonce[NONCE_BYTES];
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *decrypted;
    size_t decrypted_len;
    
    generate_random_bytes(key, KEY_BYTES);
    
    // Encrypt
    assert_int_equal(encrypt_data((const unsigned char*)plaintext, strlen(plaintext),
                                  key, &ciphertext, &ciphertext_len, nonce),
                     PWM_SUCCESS);
    
    // Tamper with ciphertext
    ciphertext[0] ^= 1;
    
    // Try to decrypt (should fail due to authentication)
    assert_int_equal(decrypt_data(ciphertext, ciphertext_len, key, nonce,
                                  &decrypted, &decrypted_len),
                     PWM_ERROR_CRYPTO);
    
    sodium_free(ciphertext);
}

// Test generate_random_bytes
static void test_generate_random_bytes(void **state) {
    (void) state;
    unsigned char buffer1[32];
    unsigned char buffer2[32];
    
    memset(buffer1, 0, 32);
    memset(buffer2, 0, 32);
    
    generate_random_bytes(buffer1, 32);
    generate_random_bytes(buffer2, 32);
    
    // Should not be all zeros
    int all_zeros = 1;
    for (int i = 0; i < 32; i++) {
        if (buffer1[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    assert_false(all_zeros);
    
    // Two calls should produce different output
    assert_memory_not_equal(buffer1, buffer2, 32);
}

// Test generate_password
static void test_generate_password_invalid_params(void **state) {
    (void) state;
    char password[100];
    
    assert_int_equal(generate_password(NULL, 20, false), PWM_ERROR_INVALID_INPUT);
    assert_int_equal(generate_password(password, 0, false), PWM_ERROR_INVALID_INPUT);
    assert_int_equal(generate_password(password, MAX_PASSWORD_LEN + 1, false), PWM_ERROR_INVALID_INPUT);
}

static void test_generate_password_valid(void **state) {
    (void) state;
    char password[50];
    
    assert_int_equal(generate_password(password, 20, false), PWM_SUCCESS);
    assert_int_equal(strlen(password), 20);
    
    // Should contain only alphanumeric characters
    for (size_t i = 0; i < strlen(password); i++) {
        assert_true(isalnum(password[i]));
    }
}

static void test_generate_password_with_symbols(void **state) {
    (void) state;
    char password[50];
    
    assert_int_equal(generate_password(password, 30, true), PWM_SUCCESS);
    assert_int_equal(strlen(password), 30);
    
    // Should be printable
    for (size_t i = 0; i < strlen(password); i++) {
        assert_true(isprint(password[i]));
    }
}

static void test_generate_password_randomness(void **state) {
    (void) state;
    char password1[30];
    char password2[30];
    
    assert_int_equal(generate_password(password1, 25, false), PWM_SUCCESS);
    assert_int_equal(generate_password(password2, 25, false), PWM_SUCCESS);
    
    // Should be different
    assert_string_not_equal(password1, password2);
}

// Test generate_username
static void test_generate_username_invalid_params(void **state) {
    (void) state;
    char username[100];
    
    assert_int_equal(generate_username(NULL, 10), PWM_ERROR_INVALID_INPUT);
    assert_int_equal(generate_username(username, 0), PWM_ERROR_INVALID_INPUT);
    assert_int_equal(generate_username(username, MAX_USERNAME_LEN + 1), PWM_ERROR_INVALID_INPUT);
}

static void test_generate_username_valid(void **state) {
    (void) state;
    char username[50];
    
    assert_int_equal(generate_username(username, 12), PWM_SUCCESS);
    assert_int_equal(strlen(username), 12);
    
    // First character should be a letter
    assert_true(isalpha(username[0]));
    
    // Rest should be alphanumeric
    for (size_t i = 0; i < strlen(username); i++) {
        assert_true(isalnum(username[i]));
    }
}

// Test secure_zero
static void test_secure_zero(void **state) {
    (void) state;
    char buffer[32];
    
    memset(buffer, 'A', 32);
    secure_zero(buffer, 32);
    
    for (int i = 0; i < 32; i++) {
        assert_int_equal(buffer[i], 0);
    }
}

static void test_secure_zero_null_ptr(void **state) {
    (void) state;
    // Should not crash
    secure_zero(NULL, 32);
}

// Test secure_alloc and secure_free
static void test_secure_alloc_free(void **state) {
    (void) state;
    void *ptr = secure_alloc(100);
    
    assert_non_null(ptr);
    
    // Write some data
    memset(ptr, 'X', 100);
    
    secure_free(ptr);
}

static void test_secure_free_null(void **state) {
    (void) state;
    // Should not crash
    secure_free(NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_crypto_init_success),
        
        cmocka_unit_test(test_derive_key_null_parameters),
        cmocka_unit_test(test_derive_key_consistency),
        cmocka_unit_test(test_derive_key_different_passwords),
        cmocka_unit_test(test_derive_key_different_salts),
        
        cmocka_unit_test(test_encrypt_data_null_parameters),
        cmocka_unit_test(test_encrypt_decrypt_roundtrip),
        cmocka_unit_test(test_decrypt_wrong_key),
        cmocka_unit_test(test_decrypt_tampered_data),
        
        cmocka_unit_test(test_generate_random_bytes),
        
        cmocka_unit_test(test_generate_password_invalid_params),
        cmocka_unit_test(test_generate_password_valid),
        cmocka_unit_test(test_generate_password_with_symbols),
        cmocka_unit_test(test_generate_password_randomness),
        
        cmocka_unit_test(test_generate_username_invalid_params),
        cmocka_unit_test(test_generate_username_valid),
        
        cmocka_unit_test(test_secure_zero),
        cmocka_unit_test(test_secure_zero_null_ptr),
        
        cmocka_unit_test(test_secure_alloc_free),
        cmocka_unit_test(test_secure_free_null),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}

