#include "aes.h"
#include <openssl/evp.h>

namespace aes {

static const EVP_CIPHER* gcm_cipher_for_keylen(size_t keylen) {
    return keylen == 16 ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
}

GcmOutput gcm_encrypt(const Bytes& key, const Bytes& iv,
                      const Bytes& plaintext, const Bytes& aad) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, gcm_cipher_for_keylen(key.size()), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

    int outlen = 0;
    if (!aad.empty())
        EVP_EncryptUpdate(ctx, nullptr, &outlen, aad.data(), (int)aad.size());

    Bytes ct(plaintext.size() + 16);
    int len = 0, total = 0;
    EVP_EncryptUpdate(ctx, ct.data(), &len, plaintext.data(), (int)plaintext.size());
    total = len;
    EVP_EncryptFinal_ex(ctx, ct.data() + total, &len);
    total += len;
    ct.resize(total);

    Bytes tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    return {ct, tag};
}

Bytes gcm_decrypt(const Bytes& key, const Bytes& iv,
                  const Bytes& ciphertext, const Bytes& tag,
                  const Bytes& aad) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, gcm_cipher_for_keylen(key.size()), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

    int outlen = 0;
    if (!aad.empty())
        EVP_DecryptUpdate(ctx, nullptr, &outlen, aad.data(), (int)aad.size());

    Bytes plain(ciphertext.size() + 16);
    int len = 0, total = 0;
    EVP_DecryptUpdate(ctx, plain.data(), &len, ciphertext.data(), (int)ciphertext.size());
    total = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(),
                        const_cast<uint8_t*>(tag.data()));
    int rc = EVP_DecryptFinal_ex(ctx, plain.data() + total, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (rc <= 0)
        throw std::runtime_error("aes::gcm_decrypt: authentication tag mismatch");
    total += len;
    plain.resize(total);
    return plain;
}

} // namespace aes
