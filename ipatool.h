#pragma once
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#endif

// ── In-memory encryption ──────────────────────────────────────────────────────
// Sensitive fields (passwordToken, password) are AES-GCM encrypted in RAM.
// The key is never stored — derived fresh on every encrypt/decrypt call:
//   key = SHA-256(get_machine_id() + "nice_key_is_nice" + g_passphrase)
// Immediately wiped after use via SecureZeroMemory/explicit_bzero.
// Only g_passphrase (which the user already knows) is kept between calls.
// g_machine_id_fn must be set to &get_machine_id from main.cpp after hwid.h
// is included — avoids circular dependency between ipatool.h and hwid.h.

static const int MEM_IV_LEN  = 12;
static const int MEM_TAG_LEN = 16;

// Set from main.cpp after hwid.h is included — avoids circular dependency.
static std::string (*g_machine_id_fn)() = nullptr;

// Only the passphrase is stored — machine_id derived fresh each call.
static std::string g_passphrase;

static void init_mem_passphrase(const std::string& passphrase) {
    g_passphrase = passphrase;
}

static void wipe_mem_passphrase() {
#ifdef _WIN32
    if (!g_passphrase.empty())
        SecureZeroMemory(g_passphrase.data(), g_passphrase.size());
#else
    if (!g_passphrase.empty())
        explicit_bzero(g_passphrase.data(), g_passphrase.size());
#endif
    g_passphrase.clear();
}

// Derive a fresh 32-byte mem key each call, use it, wipe immediately.
static void with_mem_key(const std::function<void(const unsigned char*)>& fn) {
    static const char* MEM_KEY_SALT = "nice_key_is_nice";
    // Recompute machine_id fresh via function pointer — never cached
    std::string machine_id = g_machine_id_fn ? g_machine_id_fn() : "";
    std::string input = machine_id + MEM_KEY_SALT + g_passphrase;
#ifdef _WIN32
    SecureZeroMemory(machine_id.data(), machine_id.size());
#else
    explicit_bzero(machine_id.data(), machine_id.size());
#endif
    unsigned char key[32];
    unsigned int  key_len = 32;
    EVP_Digest(input.data(), input.size(), key, &key_len, EVP_sha256(), nullptr);
#ifdef _WIN32
    SecureZeroMemory(input.data(), input.size());
#else
    explicit_bzero(input.data(), input.size());
#endif
    fn(key);
#ifdef _WIN32
    SecureZeroMemory(key, sizeof(key));
#else
    explicit_bzero(key, sizeof(key));
#endif
}

inline std::vector<unsigned char> mem_encrypt(const std::string& plaintext) {
    unsigned char iv[MEM_IV_LEN];
    RAND_bytes(iv, MEM_IV_LEN);

    std::vector<unsigned char> ct(plaintext.size() + 16);
    unsigned char tag[MEM_TAG_LEN];
    int total = 0;

    with_mem_key([&](const unsigned char* key) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MEM_IV_LEN, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
        int len = 0;
        EVP_EncryptUpdate(ctx, ct.data(), &len,
                          (const unsigned char*)plaintext.data(), (int)plaintext.size());
        total = len;
        EVP_EncryptFinal_ex(ctx, ct.data() + total, &len);
        total += len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MEM_TAG_LEN, tag);
        EVP_CIPHER_CTX_free(ctx);
    });
    ct.resize(total);

    std::vector<unsigned char> out;
    out.insert(out.end(), iv,  iv  + MEM_IV_LEN);
    out.insert(out.end(), tag, tag + MEM_TAG_LEN);
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

inline std::string mem_decrypt(const std::vector<unsigned char>& blob) {
    if (blob.size() < (size_t)(MEM_IV_LEN + MEM_TAG_LEN))
        throw std::runtime_error("mem_decrypt: blob too short");
    const unsigned char* iv = blob.data();
    unsigned char tag[MEM_TAG_LEN];
    memcpy(tag, blob.data() + MEM_IV_LEN, MEM_TAG_LEN);
    const unsigned char* ct = blob.data() + MEM_IV_LEN + MEM_TAG_LEN;
    size_t ct_len = blob.size() - MEM_IV_LEN - MEM_TAG_LEN;

    std::vector<unsigned char> plain(ct_len + 16);
    int total = 0;
    bool ok = false;

    with_mem_key([&](const unsigned char* key) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MEM_IV_LEN, nullptr);
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, MEM_TAG_LEN, (void*)tag);
        int len = 0;
        EVP_DecryptUpdate(ctx, plain.data(), &len, ct, (int)ct_len);
        total = len;
        int ret = EVP_DecryptFinal_ex(ctx, plain.data() + total, &len);
        EVP_CIPHER_CTX_free(ctx);
        ok = (ret > 0);
        if (ok) total += len;
    });

    if (!ok) throw std::runtime_error("mem_decrypt: authentication failed");
    return std::string((char*)plain.data(), total);
}

// SecureString: holds a sensitive string AES-GCM encrypted in memory.
struct SecureString {
    std::vector<unsigned char> blob;

    SecureString() = default;
    explicit SecureString(const std::string& s) { set(s); }

    void set(const std::string& s) {
        if (s.empty()) { blob.clear(); return; }
        blob = mem_encrypt(s);
    }

    bool empty() const { return blob.empty(); }

    std::string get() const {
        if (blob.empty()) return "";
        return mem_decrypt(blob);
    }

    // RAII guard: decrypts on construction, wipes plaintext on destruction
    struct Guard {
        std::string value;
        explicit Guard(const std::string& v) : value(v) {}
        ~Guard() {
#ifdef _WIN32
            if (!value.empty()) SecureZeroMemory(value.data(), value.size());
#else
            if (!value.empty()) explicit_bzero(value.data(), value.size());
#endif
        }
        const std::string& str() const { return value; }
        operator const std::string&() const { return value; }
    };

    Guard decrypt() const { return Guard(get()); }
};

// ── Constants ────────────────────────────────────────────────────────────────

static const char* ITUNES_API_DOMAIN      = "itunes.apple.com";
static const char* ITUNES_API_PATH_SEARCH = "/search";
static const char* ITUNES_API_PATH_LOOKUP = "/lookup";

static const char* PRIVATE_INIT_DOMAIN    = "init.itunes.apple.com";
static const char* PRIVATE_INIT_PATH      = "/bag.xml";

static const char* PRIVATE_AS_DOMAIN         = "buy.itunes.apple.com";
static const char* PRIVATE_AS_PATH_PURCHASE  = "/WebObjects/MZFinance.woa/wa/buyProduct";
static const char* PRIVATE_AS_PATH_DOWNLOAD  = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct";

static const char* HTTP_HEADER_STOREFRONT = "X-Set-Apple-Store-Front";
static const char* HTTP_HEADER_POD        = "pod";

static const char* FAILURE_INVALID_CREDENTIALS      = "-5000";
static const char* FAILURE_PASSWORD_TOKEN_EXPIRED   = "2034";
static const char* FAILURE_LICENSE_NOT_FOUND        = "9610";
static const char* FAILURE_TEMPORARILY_UNAVAILABLE  = "2059";

static const char* CUSTOMER_MSG_BAD_LOGIN           = "MZFinance.BadLogin.Configurator_message";
static const char* CUSTOMER_MSG_ACCOUNT_DISABLED    = "Your account is disabled.";
static const char* CUSTOMER_MSG_SUBSCRIPTION_REQ    = "Subscription Required";
static const char* CUSTOMER_MSG_SIGN_IN             = "Sign In to the iTunes Store";

static const char* PRICING_APPSTORE    = "STDQ";
static const char* PRICING_ARCADE      = "GAME";



// ── Data types ───────────────────────────────────────────────────────────────

struct Account {
    std::string   email;
    SecureString  passwordToken;  // encrypted in memory
    std::string   directoryServicesID;
    std::string   name;
    std::string   firstName;
    std::string   lastName;
    std::string   storeFront;
    SecureString  password;       // encrypted in memory
    std::string   pod;
};

struct App {
    int64_t     id        = 0;
    std::string bundleID;
    std::string name;
    std::string version;
    double      price     = 0.0;
};

struct Sinf {
    int64_t             id   = 0;
    std::vector<uint8_t> data;
};

// Progress callback: called with (bytes_so_far, total_bytes)
using ProgressCb = std::function<void(int64_t, int64_t)>;

// ── Error types ──────────────────────────────────────────────────────────────

struct IpaError : std::runtime_error {
    explicit IpaError(const std::string& msg) : std::runtime_error(msg) {}
};
struct AuthCodeRequired    : IpaError { AuthCodeRequired()    : IpaError("auth code is required") {} };
struct LicenseRequired     : IpaError { LicenseRequired()     : IpaError("license is required") {} };
struct PasswordTokenExpired: IpaError { PasswordTokenExpired(): IpaError("password token is expired") {} };
struct SubscriptionRequired: IpaError { SubscriptionRequired(): IpaError("subscription required") {} };
struct PaidAppNotSupported : IpaError { PaidAppNotSupported() : IpaError("purchasing paid apps is not supported") {} };
