#include "sha2.h"
#include <mbedtls/version.h>   // MBEDTLS_VERSION_MAJOR
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <stdexcept>

// mbedTLS 2.x vs 3.x API shim. At the 2.x→3.x boundary the int-returning entry
// points lost their "_ret" suffix (the old unsuffixed names returned void and
// were deprecated). Map the 3.x name we call onto the 2.x one so one code path
// builds against both. PBKDF2 also changed shape (2.x takes an md context, 3.x
// an md type), handled inline in pbkdf2() below.
#if MBEDTLS_VERSION_MAJOR < 3
#  define mbedtls_sha256 mbedtls_sha256_ret
#endif

// SHA-256 / HMAC-SHA256 / PBKDF2-HMAC-SHA256 via mbedTLS. All are standard
// algorithms, so output is byte-identical to the previous OpenSSL EVP
// implementation for the same inputs — account-file keys (PBKDF2) and any
// stored digests remain valid across the switch.

namespace sha2 {

Bytes digest(const uint8_t* data, size_t len) {
    Bytes out(32);
    if (mbedtls_sha256(data, len, out.data(), /*is224=*/0) != 0)
        throw std::runtime_error("sha2::digest: SHA-256 failed");
    return out;
}

Bytes digest(const Bytes& data) {
    return digest(data.data(), data.size());
}

Bytes digest(const std::string& data) {
    return digest(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

Bytes hmac(const Bytes& key, const Bytes& data) {
    Bytes out(32);
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info ||
        mbedtls_md_hmac(info, key.data(), key.size(),
                        data.data(), data.size(), out.data()) != 0)
        throw std::runtime_error("sha2::hmac: HMAC-SHA256 failed");
    return out;
}

Bytes hmac(const Bytes& key, const std::string& data) {
    return hmac(key, Bytes(data.begin(), data.end()));
}

Bytes pbkdf2(const std::string& password, const uint8_t* salt, int salt_len,
             int iterations, int keylen) {
    Bytes out(keylen);
#if MBEDTLS_VERSION_MAJOR < 3
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
#else
    // 3.x: the md type is passed directly; no context to manage.
    int rc = mbedtls_pkcs5_pbkdf2_hmac_ext(
        MBEDTLS_MD_SHA256,
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt, static_cast<size_t>(salt_len),
        static_cast<unsigned>(iterations),
        static_cast<uint32_t>(keylen), out.data());
#endif
    if (rc != 0)
        throw std::runtime_error("sha2::pbkdf2: PBKDF2-HMAC-SHA256 failed");
    return out;
}

} // namespace sha2
