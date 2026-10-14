#include "aes.h"
#include <mbedtls/gcm.h>

namespace aes {

// AES-GCM via mbedTLS. Key length selects the cipher: 16 bytes → AES-128-GCM,
// 32 bytes → AES-256-GCM (keybits = key.size() * 8). Output is byte-identical to
// the previous OpenSSL EVP implementation for the same key/iv/aad/plaintext, so
// existing account files stay decryptable.

GcmOutput gcm_encrypt(const Bytes& key, const Bytes& iv,
                      const Bytes& plaintext, const Bytes& aad) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                           key.data(), static_cast<unsigned>(key.size() * 8)) != 0) {
        mbedtls_gcm_free(&ctx);
        throw std::runtime_error("aes::gcm_encrypt: setkey failed");
    }

    Bytes ct(plaintext.size());
    Bytes tag(16);
    int rc = mbedtls_gcm_crypt_and_tag(
        &ctx, MBEDTLS_GCM_ENCRYPT, plaintext.size(),
        iv.data(), iv.size(),
        aad.data(), aad.size(),
        plaintext.data(), ct.data(),
        tag.size(), tag.data());
    mbedtls_gcm_free(&ctx);

    if (rc != 0)
        throw std::runtime_error("aes::gcm_encrypt: encryption failed");
    return {ct, tag};
}

Bytes gcm_decrypt(const Bytes& key, const Bytes& iv,
                  const Bytes& ciphertext, const Bytes& tag,
                  const Bytes& aad) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                           key.data(), static_cast<unsigned>(key.size() * 8)) != 0) {
        mbedtls_gcm_free(&ctx);
        throw std::runtime_error("aes::gcm_decrypt: setkey failed");
    }

    Bytes plain(ciphertext.size());
    int rc = mbedtls_gcm_auth_decrypt(
        &ctx, ciphertext.size(),
        iv.data(), iv.size(),
        aad.data(), aad.size(),
        tag.data(), tag.size(),
        ciphertext.data(), plain.data());
    mbedtls_gcm_free(&ctx);

    // MBEDTLS_ERR_GCM_AUTH_FAILED (or any non-zero) → tag mismatch / corruption.
    if (rc != 0)
        throw std::runtime_error("aes::gcm_decrypt: authentication tag mismatch");
    return plain;
}

} // namespace aes
