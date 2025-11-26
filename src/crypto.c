#include "crypto.h"
#include <ctype.h>

int crypto_init(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: Failed to initialize libsodium\n");
        return PWM_ERROR_CRYPTO;
    }
    return PWM_SUCCESS;
}

int derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    if (!password || !salt || !key) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    if (crypto_pwhash(
            key, KEY_BYTES,
            password, strlen(password),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return PWM_ERROR_CRYPTO;
    }
    
    return PWM_SUCCESS;
}

int encrypt_data(const unsigned char *plaintext, size_t plaintext_len,
                 const unsigned char *key, unsigned char **ciphertext,
                 size_t *ciphertext_len, unsigned char *nonce) {
    if (!plaintext || !key || !ciphertext || !ciphertext_len || !nonce) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    *ciphertext_len = MAC_BYTES + plaintext_len;
    *ciphertext = sodium_malloc(*ciphertext_len);
    
    if (!*ciphertext) {
        return PWM_ERROR_MEMORY;
    }
    
    randombytes_buf(nonce, NONCE_BYTES);
    
    if (crypto_secretbox_easy(*ciphertext, plaintext, plaintext_len,
                              nonce, key) != 0) {
        sodium_free(*ciphertext);
        *ciphertext = NULL;
        return PWM_ERROR_CRYPTO;
    }
    
    return PWM_SUCCESS;
}

int decrypt_data(const unsigned char *ciphertext, size_t ciphertext_len,
                 const unsigned char *key, const unsigned char *nonce,
                 unsigned char **plaintext, size_t *plaintext_len) {
    if (!ciphertext || !key || !nonce || !plaintext || !plaintext_len) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    if (ciphertext_len < MAC_BYTES) {
        return PWM_ERROR_CRYPTO;
    }
    
    *plaintext_len = ciphertext_len - MAC_BYTES;
    *plaintext = sodium_malloc(*plaintext_len + 1); // +1 for null terminator
    
    if (!*plaintext) {
        return PWM_ERROR_MEMORY;
    }
    
    if (crypto_secretbox_open_easy(*plaintext, ciphertext, ciphertext_len,
                                    nonce, key) != 0) {
        sodium_free(*plaintext);
        *plaintext = NULL;
        return PWM_ERROR_CRYPTO;
    }
    
    (*plaintext)[*plaintext_len] = '\0'; // Null terminate
    
    return PWM_SUCCESS;
}

void generate_random_bytes(unsigned char *buffer, size_t length) {
    randombytes_buf(buffer, length);
}

int generate_password(char *password, size_t length, bool use_symbols) {
    if (!password || length == 0 || length > MAX_PASSWORD_LEN) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    const char *charset_alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const char *charset_symbols = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
    
    const char *charset = use_symbols ? charset_symbols : charset_alpha;
    size_t charset_len = strlen(charset);
    
    for (size_t i = 0; i < length; i++) {
        uint32_t random_index = randombytes_uniform((uint32_t)charset_len);
        password[i] = charset[random_index];
    }
    password[length] = '\0';
    
    return PWM_SUCCESS;
}

int generate_username(char *username, size_t length) {
    if (!username || length == 0 || length > MAX_USERNAME_LEN) {
        return PWM_ERROR_INVALID_INPUT;
    }
    
    const char *charset = "abcdefghijklmnopqrstuvwxyz0123456789";
    size_t charset_len = strlen(charset);
    
    // Start with a letter
    uint32_t random_index = randombytes_uniform(26);
    username[0] = 'a' + random_index;
    
    for (size_t i = 1; i < length; i++) {
        random_index = randombytes_uniform((uint32_t)charset_len);
        username[i] = charset[random_index];
    }
    username[length] = '\0';
    
    return PWM_SUCCESS;
}

void secure_zero(void *ptr, size_t len) {
    if (ptr) {
        sodium_memzero(ptr, len);
    }
}

void* secure_alloc(size_t size) {
    void *ptr = sodium_malloc(size);
    if (ptr) {
        sodium_mlock(ptr, size);
    }
    return ptr;
}

void secure_free(void *ptr) {
    if (ptr) {
        sodium_free(ptr);
    }
}

