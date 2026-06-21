#pragma once
// aes.h — AES-256-GCM encryption.
//
// Used by two call sites in the project, previously two separate
// hand-rolled implementations:
//   - account file encryption (main.cpp)            → GCM
//   - in-RAM SecureString encryption (protect.h)     → GCM
//
// No CBC mode here — this repo has no GSA (no spd decryption), so GCM is
// the only mode ever needed. (The newer gsa25 branch's aes.h also has a
// CBC mode for that purpose — not applicable here.)

#include <vector>
#include <cstdint>
#include <stdexcept>

using Bytes = std::vector<uint8_t>;

namespace aes {

// AEAD: encrypt also produces a 16-byte auth tag; decrypt verifies it and
// throws std::runtime_error on tag mismatch. `aad` (additional authenticated
// data) is optional — pass empty Bytes{} if not needed.
//
// Key size selects cipher: 16 bytes → AES-128-GCM, 32 bytes → AES-256-GCM.

struct GcmOutput {
    Bytes ciphertext;
    Bytes tag; // always 16 bytes
};

GcmOutput gcm_encrypt(const Bytes& key, const Bytes& iv,
                      const Bytes& plaintext, const Bytes& aad = {});

// Throws std::runtime_error if the auth tag doesn't match (wrong key, or
// tampered/corrupted ciphertext).
Bytes gcm_decrypt(const Bytes& key, const Bytes& iv,
                  const Bytes& ciphertext, const Bytes& tag,
                  const Bytes& aad = {});

} // namespace aes
