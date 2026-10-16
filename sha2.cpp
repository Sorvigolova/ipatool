#include "sha2.h"
#include <mbedtls/version.h>   // MBEDTLS_VERSION_MAJOR
#include <stdexcept>

// SHA-256 / HMAC-SHA256 / PBKDF2-HMAC-SHA256. Output is byte-identical to the
// previous OpenSSL EVP implementation for the same inputs — account-file keys
// (PBKDF2) and stored digests stay valid across the switch.
//
// Backend by mbedTLS major version:
//   • 4.x       — legacy crypto removed; use PSA (psa_hash_* / psa_mac_* /
//                 psa_key_derivation_*).
//   • 2.x / 3.x — legacy mbedtls_sha256 / mbedtls_md_hmac / mbedtls_pkcs5. The
//                 int-returning entry points lost their "_ret" suffix at 2→3, so
//                 a shim maps the names; PBKDF2 also changed shape (ctx vs type).

#if MBEDTLS_VERSION_MAJOR >= 4
#  include <psa/crypto.h>
namespace { void ensure_psa() { static const psa_status_t s = psa_crypto_init(); (void)s; } }
#else
#  include <mbedtls/sha256.h>
#  include <mbedtls/md.h>
#  include <mbedtls/pkcs5.h>
#  if MBEDTLS_VERSION_MAJOR < 3
#    define mbedtls_sha256 mbedtls_sha256_ret
#  endif
#endif

namespace sha2 {

Bytes digest(const uint8_t* data, size_t len) {
    Bytes out(32);
#if MBEDTLS_VERSION_MAJOR >= 4
    ensure_psa();
    size_t ol = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, data, len, out.data(), out.size(), &ol) != PSA_SUCCESS)
        throw std::runtime_error("sha2::digest: SHA-256 failed");
#else
    if (mbedtls_sha256(data, len, out.data(), /*is224=*/0) != 0)
        throw std::runtime_error("sha2::digest: SHA-256 failed");
#endif
    return out;
}

Bytes digest(const Bytes& data)       { return digest(data.data(), data.size()); }
Bytes digest(const std::string& data) { return digest(reinterpret_cast<const uint8_t*>(data.data()), data.size()); }

Bytes hmac(const Bytes& key, const Bytes& data) {
    Bytes out(32);
#if MBEDTLS_VERSION_MAJOR >= 4
    ensure_psa();
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_key_id_t k = 0;
    if (psa_import_key(&attr, key.data(), key.size(), &k) != PSA_SUCCESS)
        throw std::runtime_error("sha2::hmac: key import failed");
    size_t ol = 0;
    psa_status_t s = psa_mac_compute(k, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                                     data.data(), data.size(),
                                     out.data(), out.size(), &ol);
    psa_destroy_key(k);
    if (s != PSA_SUCCESS)
        throw std::runtime_error("sha2::hmac: HMAC-SHA256 failed");
#else
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info ||
        mbedtls_md_hmac(info, key.data(), key.size(),
                        data.data(), data.size(), out.data()) != 0)
        throw std::runtime_error("sha2::hmac: HMAC-SHA256 failed");
#endif
    return out;
}

Bytes hmac(const Bytes& key, const std::string& data) {
    return hmac(key, Bytes(data.begin(), data.end()));
}

Bytes pbkdf2(const std::string& password, const uint8_t* salt, int salt_len,
             int iterations, int keylen) {
    Bytes out(keylen);
#if MBEDTLS_VERSION_MAJOR >= 4
    ensure_psa();
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_id_t pw = 0;
    psa_status_t s = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (s == PSA_SUCCESS)
        s = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST,
                                             static_cast<uint64_t>(iterations));
    if (s == PSA_SUCCESS)
        s = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                           salt, static_cast<size_t>(salt_len));
    if (s == PSA_SUCCESS) {
        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&attr, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
        psa_set_key_type(&attr, PSA_KEY_TYPE_PASSWORD);
        s = psa_import_key(&attr, reinterpret_cast<const uint8_t*>(password.data()),
                           password.size(), &pw);
    }
    if (s == PSA_SUCCESS)
        s = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, pw);
    if (s == PSA_SUCCESS)
        s = psa_key_derivation_output_bytes(&op, out.data(), static_cast<size_t>(keylen));
    psa_key_derivation_abort(&op);
    if (pw) psa_destroy_key(pw);
    if (s != PSA_SUCCESS)
        throw std::runtime_error("sha2::pbkdf2: PBKDF2-HMAC-SHA256 failed");
#elif MBEDTLS_VERSION_MAJOR < 3
    // 2.x: PBKDF2 runs through an explicit HMAC md context.
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int rc = (info && mbedtls_md_setup(&md_ctx, info, /*hmac=*/1) == 0)
           ? mbedtls_pkcs5_pbkdf2_hmac(
                 &md_ctx,
                 reinterpret_cast<const uint8_t*>(password.data()), password.size(),
                 salt, static_cast<size_t>(salt_len),
                 static_cast<unsigned>(iterations),
                 static_cast<uint32_t>(keylen), out.data())
           : -1;
    mbedtls_md_free(&md_ctx);
    if (rc != 0)
        throw std::runtime_error("sha2::pbkdf2: PBKDF2-HMAC-SHA256 failed");
#else
    // 3.x: the md type is passed directly; no context to manage.
    if (mbedtls_pkcs5_pbkdf2_hmac_ext(
            MBEDTLS_MD_SHA256,
            reinterpret_cast<const uint8_t*>(password.data()), password.size(),
            salt, static_cast<size_t>(salt_len),
            static_cast<unsigned>(iterations),
            static_cast<uint32_t>(keylen), out.data()) != 0)
        throw std::runtime_error("sha2::pbkdf2: PBKDF2-HMAC-SHA256 failed");
#endif
    return out;
}

} // namespace sha2
