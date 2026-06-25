#include "protect.h"
#include "aes.h"
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string.h>  // memset_s on macOS (Darwin declares it unconditionally)
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#endif

// Single definition for the global in-memory-encryption state declared
// `extern` in protect.h. Must be defined exactly once, in exactly one
// translation unit — having this as `static` in the header (the old way)
// gave every .cpp file its own private copy, silently breaking decryption
// whenever SecureString::set() and SecureString::get() were called from
// different .cpp files (e.g. set in gsa.cpp, get in main.cpp).

std::string (*g_machine_id_fn)() = nullptr;
std::string g_passphrase;

static const int MEM_IV_LEN  = 12;
static const int MEM_TAG_LEN = 16;

void secure_zero(void* ptr, size_t len) {
    if (!ptr || len == 0) return;
#ifdef _WIN32
    SecureZeroMemory(ptr, len);
#elif defined(__APPLE__)
    memset_s(ptr, len, 0, len);
#else
    explicit_bzero(ptr, len);
#endif
}

void init_mem_passphrase(const std::string& passphrase) {
    g_passphrase = passphrase;
}

void wipe_mem_passphrase() {
    if (!g_passphrase.empty())
        secure_zero(g_passphrase.data(), g_passphrase.size());
    g_passphrase.clear();
}

// Derive a fresh 32-byte mem key each call, use it, wipe immediately.
static void with_mem_key(const std::function<void(const unsigned char*)>& fn) {
    static const char* MEM_KEY_SALT = "nice_key_is_nice";
    // Recompute machine_id fresh via function pointer — never cached
    std::string machine_id = g_machine_id_fn ? g_machine_id_fn() : "";
    std::string input = machine_id + MEM_KEY_SALT + g_passphrase;
    secure_zero(machine_id.data(), machine_id.size());
    unsigned char key[32];
    unsigned int  key_len = 32;
    EVP_Digest(input.data(), input.size(), key, &key_len, EVP_sha256(), nullptr);
    secure_zero(input.data(), input.size());
    fn(key);
    secure_zero(key, sizeof(key));
}

static std::vector<unsigned char> mem_encrypt(const std::string& plaintext) {
    Bytes iv(MEM_IV_LEN);
    RAND_bytes(iv.data(), MEM_IV_LEN);
    Bytes pt(plaintext.begin(), plaintext.end());

    aes::GcmOutput result;
    with_mem_key([&](const unsigned char* key) {
        Bytes key_bytes(key, key + 32);
        result = aes::gcm_encrypt(key_bytes, iv, pt);
    });

    std::vector<unsigned char> out;
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), result.tag.begin(), result.tag.end());
    out.insert(out.end(), result.ciphertext.begin(), result.ciphertext.end());
    return out;
}

static std::string mem_decrypt(const std::vector<unsigned char>& blob) {
    if (blob.size() < (size_t)(MEM_IV_LEN + MEM_TAG_LEN))
        throw std::runtime_error("mem_decrypt: blob too short");
    Bytes iv(blob.begin(), blob.begin() + MEM_IV_LEN);
    Bytes tag(blob.begin() + MEM_IV_LEN, blob.begin() + MEM_IV_LEN + MEM_TAG_LEN);
    Bytes ct(blob.begin() + MEM_IV_LEN + MEM_TAG_LEN, blob.end());

    Bytes plain;
    bool ok = false;
    with_mem_key([&](const unsigned char* key) {
        Bytes key_bytes(key, key + 32);
        try {
            plain = aes::gcm_decrypt(key_bytes, iv, ct, tag);
            ok = true;
        } catch (const std::exception&) {
            ok = false;
        }
    });

    if (!ok) throw std::runtime_error("mem_decrypt: authentication failed");
    return std::string(plain.begin(), plain.end());
}

void SecureString::set(const std::string& s) {
    if (s.empty()) { blob.clear(); return; }
    blob = mem_encrypt(s);
}

std::string SecureString::get() const {
    if (blob.empty()) return "";
    return mem_decrypt(blob);
}

