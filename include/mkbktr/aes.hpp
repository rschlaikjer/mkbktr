#pragma once

#include <stdint.h>

#include <mkbktr.hpp>
#include <mkbktr/aes.hpp>

#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>

/* Enumerations. */
typedef enum {
  AES_MODE_ECB = MBEDTLS_CIPHER_AES_128_ECB,
  AES_MODE_CTR = MBEDTLS_CIPHER_AES_128_CTR,
  AES_MODE_XTS = MBEDTLS_CIPHER_AES_128_XTS,
  AES_MODE_CBC = MBEDTLS_CIPHER_AES_128_CBC
} aes_mode_t;

typedef enum {
  AES_DECRYPT = MBEDTLS_DECRYPT,
  AES_ENCRYPT = MBEDTLS_ENCRYPT,
} aes_operation_t;

/* Define structs. */
typedef struct {
  mbedtls_cipher_context_t cipher_enc;
  mbedtls_cipher_context_t cipher_dec;
} aes_ctx_t;

/* Function prototypes. */
aes_ctx_t *new_aes_ctx(const uint8_t *key, unsigned int key_size,
                       aes_mode_t mode);
void free_aes_ctx(aes_ctx_t *ctx);

void aes_setiv(aes_ctx_t *ctx, const uint8_t *iv, size_t l);

void aes_encrypt(aes_ctx_t *ctx, uint8_t *dst, const uint8_t *src, size_t l);
void aes_decrypt(aes_ctx_t *ctx, uint8_t *dst, const uint8_t *src, size_t l);

void aes_calculate_cmac(uint8_t *dst, uint8_t *src, size_t size,
                        const uint8_t *key);

void aes_xts_encrypt(aes_ctx_t *ctx, uint8_t *dst, const uint8_t *src, size_t l,
                     size_t sector, size_t sector_size);
void aes_xts_decrypt(aes_ctx_t *ctx, uint8_t *dst, const uint8_t *src, size_t l,
                     size_t sector, size_t sector_size);

