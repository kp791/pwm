#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"
#include <sodium.h>

// Crypto constants
#define SALT_BYTES 32
#define KEY_BYTES crypto_secretbox_KEYBYTES
#define NONCE_BYTES crypto_secretbox_NONCEBYTES
#define MAC_BYTES crypto_secretbox_MACBYTES

/**
 * Initialize libsodium library
 * Returns: 0 on success, -1 on failure
 */
int crypto_init(void);

/**
 * Derive encryption key from master password using Argon2id
 * password: master password
 * salt: random salt (SALT_BYTES)
 * key: output key buffer (KEY_BYTES)
 * Returns: 0 on success, PWM_ERROR_CRYPTO on failure
 */
int derive_key(const char *password, const unsigned char *salt, unsigned char *key);

/**
 * Encrypt data using XChaCha20-Poly1305
 * plaintext: data to encrypt
 * plaintext_len: length of plaintext
 * key: encryption key (KEY_BYTES)
 * ciphertext: output buffer (caller must free with sodium_free)
 * ciphertext_len: output length
 * nonce: output nonce (NONCE_BYTES)
 * Returns: 0 on success, PWM_ERROR_CRYPTO on failure
 */
int encrypt_data(const unsigned char *plaintext, size_t plaintext_len,
                 const unsigned char *key, unsigned char **ciphertext,
                 size_t *ciphertext_len, unsigned char *nonce);

/**
 * Decrypt data using XChaCha20-Poly1305
 * ciphertext: encrypted data
 * ciphertext_len: length of ciphertext
 * key: decryption key (KEY_BYTES)
 * nonce: nonce used for encryption (NONCE_BYTES)
 * plaintext: output buffer (caller must free with sodium_free)
 * plaintext_len: output length
 * Returns: 0 on success, PWM_ERROR_CRYPTO on failure
 */
int decrypt_data(const unsigned char *ciphertext, size_t ciphertext_len,
                 const unsigned char *key, const unsigned char *nonce,
                 unsigned char **plaintext, size_t *plaintext_len);

/**
 * Generate cryptographically secure random bytes
 * buffer: output buffer
 * length: number of bytes to generate
 */
void generate_random_bytes(unsigned char *buffer, size_t length);

/**
 * Generate secure random password
 * password: output buffer (must be at least length+1)
 * length: desired password length
 * use_symbols: include special characters
 * Returns: 0 on success, PWM_ERROR on failure
 */
int generate_password(char *password, size_t length, bool use_symbols);

/**
 * Generate secure random username
 * username: output buffer (must be at least length+1)
 * length: desired username length
 * Returns: 0 on success, PWM_ERROR on failure
 */
int generate_username(char *username, size_t length);

/**
 * Securely zero memory (not optimized away by compiler)
 * ptr: pointer to memory
 * len: length to zero
 */
void secure_zero(void *ptr, size_t len);

/**
 * Allocate secure memory for sensitive data
 * size: bytes to allocate
 * Returns: pointer to locked memory, NULL on failure
 */
void* secure_alloc(size_t size);

/**
 * Free secure memory
 * ptr: pointer allocated with secure_alloc
 */
void secure_free(void *ptr);

#endif /* CRYPTO_H */

