#pragma once
// In-memory protection for sensitive data (passwords, tokens).
//
// Sensitive fields (passwordToken, password) are AES-GCM encrypted in RAM
// via SecureString. The encryption key is never stored — it's derived
// fresh on every encrypt/decrypt call:
//   key = SHA-256(get_machine_id() + "nice_key_is_nice" + g_passphrase)
// and immediately wiped after use via secure_zero().
// Only g_passphrase (which the user already knows — it's the
// --keychain-passphrase they typed) is kept between calls.
//
// g_machine_id_fn must be set to &get_machine_id from main.cpp at startup,
// after hwid.h is included — avoids a circular dependency between this
// header and hwid.h.
//
// Declarations only — see protect.cpp for implementations.

#include <string>
#include <vector>
#include <cstddef>

// Cross-platform secure memory wipe.
// explicit_bzero is glibc-only (missing on macOS); Windows has SecureZeroMemory.
// memset_s (C11 Annex K) is available on both macOS and glibc 2.25+, used as fallback.
void secure_zero(void* ptr, size_t len);

// Set once from main() at startup (g_machine_id_fn = &get_machine_id).
//
// IMPORTANT: these MUST be true global variables (extern, defined once in
// protect.cpp), NOT `static`. A `static` global in a header gives every .cpp
// translation unit its own private copy — so SecureString::set() called from
// one .cpp would use a different (empty/default) key than SecureString::get()
// called later from another, and decryption would fail with
// "mem_decrypt: authentication failed".
extern std::string (*g_machine_id_fn)();

// Only the passphrase is stored — machine_id derived fresh each call.
extern std::string g_passphrase;

void init_mem_passphrase(const std::string& passphrase);
void wipe_mem_passphrase();

// SecureString: holds a sensitive string AES-GCM encrypted in memory.
struct SecureString {
    std::vector<unsigned char> blob;

    SecureString() = default;
    explicit SecureString(const std::string& s) { set(s); }

    void set(const std::string& s);
    std::string get() const;
    bool empty() const { return blob.empty(); }

    // RAII guard: decrypts on construction, wipes plaintext on destruction
    struct Guard {
        std::string value;
        explicit Guard(const std::string& v) : value(v) {}
        ~Guard() {
            if (!value.empty()) secure_zero(value.data(), value.size());
        }
        const std::string& str() const { return value; }
        operator const std::string&() const { return value; }
    };

    Guard decrypt() const { return Guard(get()); }
};
