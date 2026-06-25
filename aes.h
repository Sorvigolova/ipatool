#pragma once
// aes.h — AES encryption, all modes in one place (GCM + CBC).
//
// Used by three call sites in the project, previously three separate
// hand-rolled implementations:
//   - account file V3 encryption (main.cpp)            → GCM
//   - in-RAM SecureString encryption (protect.h)       → GCM
//   - GSA spd decryption (gsa.h)                        → CBC

#include <vector>
#include <cstdint>
#include <stdexcept>

using Bytes = std::vector<uint8_t>;

namespace aes {

// ── GCM ──────────────────────────────────────────────────────────────────
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

// ── CBC ──────────────────────────────────────────────────────────────────
// AES-256-CBC with PKCS7 padding. No authentication — caller must verify
// integrity another way if needed (GSA spd is inside an already-authenticated
// SRP session, so this is acceptable there).

Bytes cbc_decrypt(const Bytes& key, const Bytes& iv, const Bytes& ciphertext);
Bytes cbc_encrypt(const Bytes& key, const Bytes& iv, const Bytes& plaintext);

} // namespace aes
