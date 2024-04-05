/*
 * Copyright (c) 2022 Felix Gohla, Konrad Hanff, Tobias Kantusch,
 *                    Quentin Kuth, Felix Roth. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <aes_gcm.h>
#include <sha256.h>
#include <monocypher-ed25519.h>

#include "crypto.h"

#if defined(NO_SOFTWARE_CRYPTO_AES_GCM_ENCRYPT)
int fido_aes_gcm_encrypt_not_implemented(const uint8_t *key, size_t key_len,
                                         const uint8_t *iv, size_t iv_len,
                                         const uint8_t *plaintext, size_t plaintext_len,
                                         const uint8_t *aad, size_t aad_len,
                                         uint8_t *ciphertext, uint8_t *tag) {
  assert(0);
}
fido_aes_gcm_encrypt_t fido_aes_gcm_encrypt = &fido_aes_gcm_encrypt_not_implemented;
#else
fido_aes_gcm_encrypt_t fido_aes_gcm_encrypt = &aes_gcm_ae;
#endif

#if defined(NO_SOFTWARE_CRYPTO_AES_GCM_DECRYPT)
int fido_aes_gcm_decrypt_not_implemented(const uint8_t *key, size_t key_len,
                                         const uint8_t *iv, size_t iv_len,
                                         const uint8_t *ciphertext, size_t ciphertext_len,
                                         const uint8_t *aad, size_t aad_len,
                                         const uint8_t *tag,
                                         uint8_t *plaintext) {
  assert(0);
}
fido_aes_gcm_decrypt_t fido_aes_gcm_decrypt = &fido_aes_gcm_decrypt_not_implemented;
#else
fido_aes_gcm_decrypt_t fido_aes_gcm_decrypt = &aes_gcm_ad;
#endif

#if defined(NO_SOFTWARE_CRYPTO_ED25519_SIGN)
void crypto_ed25519_sign_not_implemented(uint8_t *signature,
                                 const uint8_t *secret_key,
                                 const uint8_t *message, size_t message_len) {
  assert(0);
}
fido_ed25519_sign_t fido_ed25519_sign = &crypto_ed2551_sign_not_implemented;
#else
void crypto_ed25519_sign_wrapper(uint8_t *signature,
                                 const uint8_t *secret_key,
                                 const uint8_t *message, size_t message_len) {
    crypto_ed25519_sign(signature, secret_key, NULL, message, (int) message_len);
}
fido_ed25519_sign_t fido_ed25519_sign = &crypto_ed25519_sign_wrapper;
#endif

#if defined(NO_SOFTWARE_CRYPTO_ED25519_VERIFY)
int crypto_ed25519_verify_not_implemented(const uint8_t *signature,
                                      const uint8_t *public_key,
                                      const uint8_t *message, size_t message_len) {
  assert(0);
  return -1;
}
fido_ed25519_verify_t fido_ed25519_verify = &crypto_ed25519_verify_not_implemented;
#else
fido_ed25519_verify_t fido_ed25519_verify = &crypto_ed25519_check;
#endif

#if defined(NO_SOFTWARE_CRYPTO_SHA256)
void crypto_sha256_not_implemented(const uint8_t *data,
                                   size_t data_len,
                                   uint8_t *hash) {
  assert(0);
}
fido_sha256_t fido_sha256 = NULL;
#else
fido_sha256_t fido_sha256 = &sha256;
#endif

#if defined(NO_SOFTWARE_CRYPTO_SHA512)
void crypto_sha512_not_implemented(const uint8_t *data, size_t data_len,
                           uint8_t *hash) {
  assert(0);
}
fido_sha512_t fido_sha512 = &crypto_sha512_not_implemented;
#else
void crypto_sha512_wrapper(const uint8_t *data, size_t data_len,
                           uint8_t *hash) {
    crypto_sha512(hash, data, (int) data_len);
}
fido_sha512_t fido_sha512 = &crypto_sha512_wrapper;
#endif
