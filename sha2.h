#pragma once
// sha2.h — SHA-256 digest and HMAC-SHA256, free-function style.
//
// HMAC-SHA256 lives here (not in aes.h) because it's a hash construction
// (HMAC = hash-based MAC), not a cipher mode — it never touches AES.

#include <string>
#include <vector>
#include <cstdint>

using Bytes = std::vector<uint8_t>;

namespace sha2 {

// Plain SHA-256 digest, returns 32 bytes.
Bytes digest(const uint8_t* data, size_t len);
Bytes digest(const Bytes& data);
Bytes digest(const std::string& data);

// HMAC-SHA256(key, data), returns 32 bytes.
Bytes hmac(const Bytes& key, const Bytes& data);
Bytes hmac(const Bytes& key, const std::string& data);

// PBKDF2-HMAC-SHA256(password, salt, iterations, keylen)
// Used for account-file encryption key derivation (hwid.h) and was
// previously also used inline in gsa.h's gsa_crypto namespace.
Bytes pbkdf2(const std::string& password, const uint8_t* salt, int salt_len,
             int iterations, int keylen);

} // namespace sha2
