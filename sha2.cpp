#include "sha2.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace sha2 {

Bytes digest(const uint8_t* data, size_t len) {
    Bytes out(32);
    unsigned int out_len = 32;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out.data(), &out_len);
    EVP_MD_CTX_free(ctx);
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
    unsigned int out_len = 32;
    HMAC(EVP_sha256(),
         key.data(), (int)key.size(),
         data.data(), data.size(),
         out.data(), &out_len);
    return out;
}

Bytes hmac(const Bytes& key, const std::string& data) {
    return hmac(key, Bytes(data.begin(), data.end()));
}

Bytes pbkdf2(const std::string& password, const uint8_t* salt, int salt_len,
             int iterations, int keylen) {
    Bytes out(keylen);
    PKCS5_PBKDF2_HMAC(
        password.c_str(), (int)password.size(),
        salt, salt_len,
        iterations, EVP_sha256(), keylen, out.data());
    return out;
}

} // namespace sha2
