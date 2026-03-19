// ipatool-cpp — C++ port of ipatool (https://github.com/majd/ipatool)
//
// Requires: libcurl, nlohmann/json, OpenSSL, minizip
//
// Account file encryption:
//   Key = PBKDF2-SHA256(machine_id + "nice_key_is_nice" + passphrase, random_salt, 100000, 32)
//   machine_id = SHA256(ProductId + MachineGuid)   on Windows
//              = SHA256(machine-id + product_uuid)  on Linux
//              = SHA256(SerialNumber + PlatformUUID) on macOS
//   File format: [0x02][salt_len(4)][salt][IV][GCM tag][ciphertext]
//
// In-memory encryption:
//   SecureString fields encrypted with AES-256-GCM
//   Key = SHA256(get_machine_id() + "nice_key_is_nice" + passphrase) — derived fresh each use, never stored
//
// Usage:
//   ipatool auth login   -e user@example.com -p password [--auth-code 123456]
//   ipatool search       "angry birds" [-l 5]
//   ipatool purchase     -b com.example.app
//   ipatool download     -b com.example.app [-o ./output.ipa]

#include "appstore.h"
#include "hwid.h"

// Wire up machine ID function pointer for in-memory encryption (ipatool.h)
// Must be done here since hwid.h is not visible from ipatool.h
namespace { const bool _mid_init = (g_machine_id_fn = &get_machine_id, true); }

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <vector>
#include <functional>
#include <cstring>
#include <chrono>
#include <csignal>
#include <nlohmann/json.hpp>
#include <filesystem>
#ifndef _WIN32
#  include <sys/ioctl.h>
#  include <unistd.h>
#endif

// OpenSSL for AES-256-GCM encryption of the account file
#include <openssl/evp.h>
#include <openssl/rand.h>

// Platform-specific TTY detection and hidden input
#ifdef _WIN32
#  include <conio.h>
#  include <io.h>
static bool is_tty() { return _isatty(_fileno(stdin)) != 0; }
static std::string read_hidden(const std::string& prompt) {
    std::cerr << prompt << std::flush;
    std::string s;
    int c;
    while ((c = _getch()) != '\r' && c != '\n' && c != EOF) {
        if (c == '\b') {
            if (!s.empty()) {
                s.pop_back();
                std::cerr << "\b \b" << std::flush; // erase last *
            }
        } else if (c >= 32) { // printable chars only
            s += (char)c;
            std::cerr << '*' << std::flush;
        }
    }
    std::cerr << "\n";
    return s;
}
#else
#  include <termios.h>
#  include <unistd.h>
static bool is_tty() { return isatty(fileno(stdin)) != 0; }
static std::string read_hidden(const std::string& prompt) {
    std::cerr << prompt << std::flush;
    struct termios oldt, newt;
    tcgetattr(fileno(stdin), &oldt);
    newt = oldt;
    newt.c_lflag &= ~(tcflag_t)(ECHO | ICANON); // char-by-char, no echo
    newt.c_cc[VMIN]  = 1;
    newt.c_cc[VTIME] = 0;
    tcsetattr(fileno(stdin), TCSANOW, &newt);
    std::string s;
    int c;
    while ((c = getchar()) != '\n' && c != '\r' && c != EOF) {
        if (c == 127 || c == '\b') { // backspace
            if (!s.empty()) {
                s.pop_back();
                std::cerr << "\b \b" << std::flush;
            }
        } else if (c >= 32) {
            s += (char)c;
            std::cerr << '*' << std::flush;
        }
    }
    tcsetattr(fileno(stdin), TCSANOW, &oldt);
    std::cerr << "\n";
    return s;
}
#endif

static std::string read_line(const std::string& prompt) {
    std::cerr << prompt << std::flush;
    std::string s;
    std::getline(std::cin, s);
    return s;
}


using json = nlohmann::json;

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::string home_dir() {
    const char* home = getenv("HOME");
#ifdef _WIN32
    if (!home) home = getenv("USERPROFILE");
#endif
    return home ? home : ".";
}

// Matches original ipatool directory layout exactly:
//   ~/.ipatool/account  (keyring FileBackend key="account"; plain or encrypted, same filename)
//   ~/.ipatool/cookies  (libcurl cookie jar — matches CookieJarFileName constant)
static const std::string CONFIG_DIR   = home_dir() + "/.ipatool";
static const std::string ACCOUNT_FILE = CONFIG_DIR + "/account";
static const std::string COOKIE_FILE  = CONFIG_DIR + "/cookies";

// Ensure ~/.ipatool/ exists
static void ensure_config_dir() {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::create_directories(CONFIG_DIR, ec);
}

// ── AES-256-GCM file encryption ───────────────────────────────────────────────
// Format v2 (the only supported format):
//   [1 byte: 0x02][4 bytes: salt_len][16 bytes: salt][12 bytes: IV][16 bytes: GCM tag][ciphertext]
//
// Key = PBKDF2-SHA256(machine_id + "nice_key_is_nice" + passphrase, random_salt, 100000, 32)
// passphrase may be "" — machine binding alone is sufficient.
// Plaintext and old-format files are rejected — re-login required.

static const uint8_t FILE_FORMAT_V2  = 0x02;
static const int     SALT_LEN        = 16;
static const int     IV_LEN          = 12;
static const int     TAG_LEN         = 16;
static const int     KEY_LEN         = 32; // AES-256

// Derive file encryption key: PBKDF2-SHA256(machine_id + "nice_key_is_nice" + passphrase, random_salt, 100000, 32)
static bool derive_file_key(const std::string& machine_id,
                             const std::string& passphrase,
                             const unsigned char* salt, int salt_len,
                             unsigned char* key_out) {
    return derive_key_from_machine(machine_id, passphrase, salt, salt_len, key_out);
}

// Encrypt plaintext → v2 binary blob
static std::vector<unsigned char> aes_gcm_encrypt(const std::string& plaintext,
                                                    const std::string& machine_id,
                                                    const std::string& passphrase) {
    unsigned char salt[SALT_LEN], iv[IV_LEN], key[KEY_LEN], tag[TAG_LEN];
    RAND_bytes(salt, SALT_LEN);
    RAND_bytes(iv,   IV_LEN);
    if (!derive_file_key(machine_id, passphrase, salt, SALT_LEN, key))
        throw std::runtime_error("key derivation failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);

    std::vector<unsigned char> ct(plaintext.size() + 16);
    int len = 0, total = 0;
    EVP_EncryptUpdate(ctx, ct.data(), &len,
                      (const unsigned char*)plaintext.data(), (int)plaintext.size());
    total = len;
    EVP_EncryptFinal_ex(ctx, ct.data() + total, &len);
    total += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);
    ct.resize(total);

    // Pack: version(1) | salt_len(4) | salt | iv | tag | ciphertext
    std::vector<unsigned char> out;
    out.push_back(FILE_FORMAT_V2);
    uint32_t sl = SALT_LEN;
    out.insert(out.end(), (unsigned char*)&sl, (unsigned char*)&sl + 4);
    out.insert(out.end(), salt, salt + SALT_LEN);
    out.insert(out.end(), iv,   iv   + IV_LEN);
    out.insert(out.end(), tag,  tag  + TAG_LEN);
    out.insert(out.end(), ct.begin(), ct.end());

    // Wipe key material from stack
#ifdef _WIN32
    SecureZeroMemory(key, KEY_LEN);
#else
    explicit_bzero(key, KEY_LEN);
#endif
    return out;
}

// Decrypt v2 binary blob → plaintext
static std::string aes_gcm_decrypt(const std::vector<unsigned char>& blob,
                                    const std::string& machine_id,
                                    const std::string& passphrase) {
    if (blob.empty())
        throw std::runtime_error("account file is empty or corrupted");

    if (blob[0] == '{')
        throw std::runtime_error(
            "account file is unencrypted — please run 'auth login' again");

    if (blob[0] != FILE_FORMAT_V2)
        throw std::runtime_error(
            "account file format is outdated — please run 'auth login' again");

    if (blob.size() < (size_t)(1 + 4 + SALT_LEN + IV_LEN + TAG_LEN))
        throw std::runtime_error("account file is too short or corrupted");

    const unsigned char* p = blob.data() + 1;
    uint32_t sl;
    memcpy(&sl, p, 4); p += 4;
    if (sl != SALT_LEN || blob.size() < (size_t)(1 + 4 + sl + IV_LEN + TAG_LEN))
        throw std::runtime_error("account file is corrupted");

    const unsigned char* salt = p; p += sl;
    const unsigned char* iv   = p; p += IV_LEN;
    unsigned char tag[TAG_LEN];
    memcpy(tag, p, TAG_LEN); p += TAG_LEN;
    size_t ct_len = blob.size() - (size_t)(p - blob.data());

    unsigned char key[KEY_LEN];
    if (!derive_file_key(machine_id, passphrase, salt, (int)sl, key))
        throw std::runtime_error("key derivation failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

    std::vector<unsigned char> plain(ct_len + 16);
    int len = 0, total = 0;
    EVP_DecryptUpdate(ctx, plain.data(), &len, p, (int)ct_len);
    total = len;
    int ret = EVP_DecryptFinal_ex(ctx, plain.data() + total, &len);
    EVP_CIPHER_CTX_free(ctx);

#ifdef _WIN32
    SecureZeroMemory(key, KEY_LEN);
#else
    explicit_bzero(key, KEY_LEN);
#endif

    if (ret <= 0)
        throw std::runtime_error("decryption failed — wrong device or passphrase");
    total += len;
    return std::string((char*)plain.data(), total);
}


// ── In-memory encryption ──────────────────────────────────────────────────────
// g_passphrase and with_mem_key are defined in ipatool.h.
// machine_id is recomputed fresh on every encrypt/decrypt call.

// Forward declaration — defined after color init below
static void print_red_err(const std::string& msg);

static bool save_account(const Account& acc, const std::string& passphrase = "") {
    ensure_config_dir();

    std::string machine_id = get_machine_id();

    json j;
    j["email"]               = std::string(acc.email);
    j["passwordToken"]       = acc.passwordToken.get();
    j["directoryServicesID"] = std::string(acc.directoryServicesID);
    j["name"]                = std::string(acc.name);
    j["firstName"]           = std::string(acc.firstName);
    j["lastName"]            = std::string(acc.lastName);
    j["storeFront"]          = std::string(acc.storeFront);
    j["password"]            = acc.password.get();
    j["pod"]                 = std::string(acc.pod);
    std::string data = j.dump(2);

    try {
        auto blob = aes_gcm_encrypt(data, machine_id, passphrase);
        std::ofstream f(ACCOUNT_FILE, std::ios::binary);
        if (!f) {
            print_red_err("Error: failed to write account file.\n");
            return false;
        }
        f.write((const char*)blob.data(), blob.size());
    } catch (const std::exception& e) {
        print_red_err(std::string("Error: failed to encrypt account file: ")
                      + e.what() + "\n");
        return false;
    }
    return true;
}

static bool load_account(Account& acc, const std::string& passphrase = "") {
    std::ifstream f(ACCOUNT_FILE, std::ios::binary);
    if (!f) return false;

    std::vector<unsigned char> raw((std::istreambuf_iterator<char>(f)),
                                    std::istreambuf_iterator<char>());
    if (raw.empty()) return false;

    // Reject plaintext and old formats
    if (raw[0] == '{' || raw[0] != FILE_FORMAT_V2) {
        print_red_err("Error: account file is not protected.\n"
                      "Please run 'auth login' again.\n");
        return false;
    }

    // Decrypt using current machine ID
    std::string machine_id = get_machine_id();
    std::string data;
    try {
        data = aes_gcm_decrypt(raw, machine_id, passphrase);
    } catch (const std::exception& e) {
        print_red_err(std::string("Error: failed to decrypt account file — ")
                      + e.what() + "\n"
                      + "This account file was created on a different machine "
                        "or with a different passphrase.\n"
                        "Please run 'auth login' again.\n");
        return false;
    }

    try {
        json j = json::parse(data);

        acc.email               = j.value("email", "");
        acc.directoryServicesID = j.value("directoryServicesID", "");
        acc.name                = j.value("name", "");
        acc.firstName           = j.value("firstName", "");
        acc.lastName            = j.value("lastName", "");
        acc.storeFront          = j.value("storeFront", "");
        acc.pod                 = j.value("pod", "");

        // Encrypt sensitive fields with mem key derived from machine_id
        acc.passwordToken.set(j.value("passwordToken", ""));
        acc.password.set(     j.value("password", ""));

        return true;
    } catch (...) {
        print_red_err("Error: account file is corrupted.\n");
        return false;
    }
}


// ── CLI arg parsing ───────────────────────────────────────────────────────────

struct Args {
    std::map<std::string, std::string> flags;
    std::vector<std::string>           pos;
};

static Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; i++) {
        std::string s = argv[i];
        if (s.size() > 2 && s[0]=='-' && s[1]=='-') {
            std::string key = s.substr(2);
            if (i+1 < argc && argv[i+1][0] != '-') {
                a.flags[key] = argv[++i];
            } else {
                a.flags[key] = "true";
            }
        } else if (s.size() == 2 && s[0]=='-') {
            std::string key(1, s[1]);
            if (i+1 < argc && argv[i+1][0] != '-') {
                a.flags[key] = argv[++i];
            } else {
                a.flags[key] = "true";
            }
        } else {
            a.pos.push_back(s);
        }
    }
    return a;
}

static std::string get(const Args& a, const std::string& longName,
                        const std::string& shortName = "",
                        const std::string& def = "") {
    auto it = a.flags.find(longName);
    if (it != a.flags.end()) return it->second;
    if (!shortName.empty()) {
        it = a.flags.find(shortName);
        if (it != a.flags.end()) return it->second;
    }
    return def;
}

// ── Commands ──────────────────────────────────────────────────────────────────

// ── Output format ────────────────────────────────────────────────────────────
static std::string g_format = "text"; // "text" (default) or "json"

// ── Color output ─────────────────────────────────────────────────────────────
#ifdef _WIN32

static bool s_ansi_enabled  = false;
static WORD s_defaultAttrs  = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

// ── Cursor restore (called on exit/signal to recover hidden cursor) ───────────
static void restore_cursor() {
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    CONSOLE_CURSOR_INFO cci;
    if (GetConsoleCursorInfo(h, &cci)) {
        cci.bVisible = TRUE;
        SetConsoleCursorInfo(h, &cci);
    }
}
static void signal_handler(int) { restore_cursor(); _exit(1); }

static void init_color() {
    if (!_isatty(_fileno(stdout))) return;
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE) return;
    // Save original attributes (includes background color)
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(h, &csbi))
        s_defaultAttrs = csbi.wAttributes;
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode) &&
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        s_ansi_enabled = true;
}

static bool use_color() { return _isatty(_fileno(stdout)) != 0; }

enum ColId { COL_RESET_ID, COL_DARK_ID, COL_GREEN_ID, COL_CYAN_ID, COL_RED_ID };

static void set_color(ColId c) {
    if (!use_color()) return;
    if (s_ansi_enabled) {
        switch (c) {
            case COL_RESET_ID:  std::cout << "\x1b[0m";  break;
            case COL_DARK_ID:   std::cout << "\x1b[90m"; break;
            case COL_GREEN_ID:  std::cout << "\x1b[32m"; break;
            case COL_CYAN_ID:   std::cout << "\x1b[36m"; break;
            case COL_RED_ID:    std::cout << "\x1b[31m"; break;
        }
    } else {
        // Preserve original background bits (high nibble of s_defaultAttrs)
        const WORD bg = s_defaultAttrs & 0x00F0;
        std::cout.flush();
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        switch (c) {
            case COL_RESET_ID:  SetConsoleTextAttribute(h, s_defaultAttrs); break;
            case COL_DARK_ID:   SetConsoleTextAttribute(h, bg | FOREGROUND_INTENSITY); break;
            case COL_GREEN_ID:  SetConsoleTextAttribute(h, bg | FOREGROUND_GREEN | FOREGROUND_INTENSITY); break;
            case COL_CYAN_ID:   SetConsoleTextAttribute(h, bg | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); break;
            case COL_RED_ID:    SetConsoleTextAttribute(h, bg | FOREGROUND_RED | FOREGROUND_INTENSITY); break;
        }
    }
}

#else  // POSIX

static void init_color() {}
static bool use_color() { return isatty(fileno(stdout)) != 0; }

enum ColId { COL_RESET_ID, COL_DARK_ID, COL_GREEN_ID, COL_CYAN_ID, COL_RED_ID };

static void set_color(ColId c) {
    if (!use_color()) return;
    switch (c) {
        case COL_RESET_ID:  std::cout << "\x1b[0m";  break;
        case COL_DARK_ID:   std::cout << "\x1b[90m"; break;
        case COL_GREEN_ID:  std::cout << "\x1b[32m"; break;
        case COL_CYAN_ID:   std::cout << "\x1b[36m"; break;
        case COL_RED_ID:    std::cout << "\x1b[31m"; break;
    }
}

#endif

// Print a message in red to stderr, using Console API on Win7/8 or ANSI elsewhere.
static void print_red_err(const std::string& msg) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (s_ansi_enabled) {
        std::cerr << "\x1b[31m" << msg << "\x1b[0m";
    } else {
        const WORD bg = s_defaultAttrs & 0x00F0;
        SetConsoleTextAttribute(h, bg | FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cerr << msg;
        std::cerr.flush();
        SetConsoleTextAttribute(h, s_defaultAttrs);
    }
#else
    if (use_color()) std::cerr << "\x1b[31m" << msg << "\x1b[0m";
    else             std::cerr << msg;
#endif
}

// Attempt silent re-login using stored password and update saved account.
// Returns true and updates acc on success. Returns false if password not stored.
// Used to recover from PasswordTokenExpired without user interaction.
static bool silent_relogin(Account& acc, const std::string& passphrase) {
    if (acc.password.empty()) return false;
    std::string authCode;
    for (int attempt = 0; attempt < 2; attempt++) {
        try {
            AppStore store(COOKIE_FILE);
            auto pwd = acc.password.decrypt();
            Account fresh = store.login(acc.email, pwd.str(), authCode);
            if (!save_account(fresh, passphrase)) return false;
            acc = fresh;
            return true;
        } catch (const AuthCodeRequired&) {
            if (attempt > 0) {
                print_red_err("Re-login failed: 2FA code rejected\n");
                return false;
            }
            std::cerr << "Session expired. Enter 2FA code to re-authenticate: " << std::flush;
            std::getline(std::cin, authCode);
            while (!authCode.empty() && (authCode.back() == '\r' || authCode.back() == '\n'))
                authCode.pop_back();
        } catch (const std::exception& e) {
            print_red_err(std::string("Re-login failed: ") + e.what() + "\n");
            return false;
        } catch (...) {
            print_red_err("Re-login failed: unknown error\n");
            return false;
        }
    }
    return false;
}

// Emits output matching zerolog ConsoleWriter (text) or raw JSON (json).
// text:  <HH:MM:SS> INF key=value key=value ...   (colorized on TTY)
// json:  {"key":"value",...}
static void log_output(const json& j) {
    if (g_format == "json") {
        std::cout << j.dump() << "\n";
        return;
    }
    auto now = std::time(nullptr);
    char ts[10];
    std::strftime(ts, sizeof(ts), "%H:%M:%S", std::localtime(&now));

    set_color(COL_DARK_ID);
    std::cout << ts;
    set_color(COL_RESET_ID);

    std::cout << " ";
    set_color(COL_GREEN_ID);
    std::cout << "INF";
    set_color(COL_RESET_ID);

    for (auto& [k, v] : j.items()) {
        std::cout << " ";
        set_color(COL_CYAN_ID);
        std::cout << k;
        set_color(COL_RESET_ID);
        std::cout << "=";
        if (v.is_string())       std::cout << v.get<std::string>();
        else if (v.is_boolean()) std::cout << (v.get<bool>() ? "true" : "false");
        else                     std::cout << v.dump();
    }
    std::cout << "\n";
}

static void cmd_login(const Args& args) {
    std::string email      = get(args, "email",               "e");
    std::string password   = get(args, "password",            "p");
    std::string authCode   = get(args, "auth-code",           "a");
    std::string passphrase = get(args, "keychain-passphrase", "");
    bool interactive = is_tty();

    // email is always required
    if (email.empty()) {
        if (interactive) {
            email = read_line("Enter email: ");
        }
        if (email.empty()) {
            std::cerr << "Error: email is required. Use -e EMAIL\n";
            exit(1);
        }
    }

    // password: prompt with hidden input if not supplied and interactive
    if (password.empty()) {
        if (interactive) {
            password = read_hidden("Enter password: ");
        }
        if (password.empty()) {
            std::cerr << "Error: password is required when not running interactively. Use -p PASSWORD\n";
            exit(1);
        }
    }

    AppStore store(COOKIE_FILE);
    if (get(args, "debug") == "true") store.set_debug(true);

    // Retry loop: if 2FA required, prompt for code and retry (mirrors original)
    for (int attempt = 0; attempt < 2; ++attempt) {
        try {
            Account acc = store.login(email, password, authCode);
            if (!save_account(acc, passphrase)) {
                std::cerr << "Warning: could not save account\n";
            }
            json loginOut;
            loginOut["name"]    = acc.name;
            loginOut["email"]   = acc.email;
            loginOut["success"] = true;
            log_output(loginOut);
            return;
        } catch (const AuthCodeRequired&) {
            if (interactive && authCode.empty()) {
                std::cerr << "Enter 2FA code: " << std::flush;
                std::getline(std::cin, authCode);
                // strip CR/LF
                while (!authCode.empty() && (authCode.back() == '\r' || authCode.back() == '\n'))
                    authCode.pop_back();
                continue; // retry with code
            }
            std::cerr << "Error: two-factor auth code required. Retry with --auth-code CODE\n";
            exit(1);
        } catch (const std::exception& e) {
            print_red_err(std::string("Login error: ") + e.what() + "\n");
            exit(1);
        }
    }
    print_red_err("Login failed after retry.\n");
    exit(1);
}

static void cmd_search(const Args& args) {
    // Term is a positional argument (same as original: ipatool search <term>)
    // pos[0]="search", pos[1]=term, any further positionals are ignored
    std::string term       = args.pos.size() >= 2 ? args.pos[1] : get(args, "term", "t");
    std::string limit      = get(args, "limit",               "l", "5");
    std::string passphrase = get(args, "keychain-passphrase", "");

    if (term.empty()) {
        std::cerr << "Usage: ipatool search <term> [-l LIMIT]\n";
        exit(1);
    }

    Account acc;
    if (!load_account(acc, passphrase)) {
        std::cerr << "Not logged in. Run: ipatool auth login -e EMAIL -p PASSWORD\n";
        exit(1);
    }

    AppStore store(COOKIE_FILE);
    if (get(args, "debug") == "true") store.set_debug(true);
    try {
        auto result = store.search(acc, term, std::stoi(limit));

        // Output as JSON array matching original zerolog structure:
        // {"level":"info","count":N,"apps":[{"id":...,"bundleID":...,"name":...,"version":...,"price":...}]}
        json apps = json::array();
        for (auto& app : result.results) {
            json a;
            a["id"]       = app.id;
            a["bundleID"] = app.bundleID;
            a["name"]     = app.name;
            a["version"]  = app.version;
            a["price"]    = app.price;
            apps.push_back(a);
        }
        json out;
        out["count"] = result.count;
        out["apps"]  = apps;
        log_output(out);
    } catch (const std::exception& e) {
        std::cerr << "Search error: " << e.what() << "\n";
        exit(1);
    }
}

static void cmd_purchase(const Args& args) {
    std::string bundleID   = get(args, "bundle-id",           "b");
    std::string passphrase = get(args, "keychain-passphrase", "");

    if (bundleID.empty()) {
        std::cerr << "Usage: ipatool purchase -b BUNDLE_ID\n";
        exit(1);
    }

    Account acc;
    if (!load_account(acc, passphrase)) {
        std::cerr << "Not logged in.\n";
        exit(1);
    }

    AppStore store(COOKIE_FILE);
    try {
        App app = store.lookup(acc, bundleID);
        std::cout << "Purchasing: " << app.name << " (" << app.bundleID << ")\n";
        store.purchase(acc, app);
        json purchaseOut;
        purchaseOut["success"] = true;
        log_output(purchaseOut);
    } catch (const PaidAppNotSupported&) {
        print_red_err("Error: purchasing paid apps is not supported.\n");
        exit(1);
    } catch (const PasswordTokenExpired&) {
        if (!silent_relogin(acc, passphrase)) {
            print_red_err("Error: session expired. Please log in again.\n");
            exit(1);
        }
        try {
            App app = store.lookup(acc, bundleID);
            store.purchase(acc, app);
            json purchaseOut;
            purchaseOut["success"] = true;
            log_output(purchaseOut);
        } catch (const std::exception& e2) {
            print_red_err(std::string("Purchase error: ") + e2.what() + "\n");
            exit(1);
        }
    } catch (const std::exception& e) {
        print_red_err(std::string("Purchase error: ") + e.what() + "\n");
        exit(1);
    }
}

static void cmd_show_account(const Args& args) {
    std::string passphrase = get(args, "keychain-passphrase", "");
    Account acc;
    if (!load_account(acc, passphrase)) {
        std::cerr << "Not logged in.\n";
        exit(1);
    }
    json out;
    out["name"]    = acc.name;
    out["email"]   = acc.email;
    out["success"] = true;
    log_output(out);
}

static void cmd_list_versions(const Args& args) {
    std::string bundleID   = get(args, "bundle-id",           "b");
    std::string appIDStr   = get(args, "app-id",              "i");
    std::string passphrase = get(args, "keychain-passphrase", "");

    if (bundleID.empty() && appIDStr.empty()) {
        std::cerr << "Usage: ipatool list-versions (-b BUNDLE_ID | -i APP_ID)\n";
        exit(1);
    }

    Account acc;
    if (!load_account(acc, passphrase)) { std::cerr << "Not logged in.\n"; exit(1); }

    AppStore store(COOKIE_FILE);
    if (get(args, "debug") == "true") store.set_debug(true);
    try {
        App app;
        if (!bundleID.empty()) {
            app = store.lookup(acc, bundleID);
        } else {
            app.id = std::stoll(appIDStr);
        }

        auto out = store.list_versions(acc, app);

        json j;
        j["externalVersionIdentifiers"] = out.externalVersionIdentifiers;
        j["bundleID"]                   = app.bundleID;
        j["success"]                    = true;
        log_output(j);
    } catch (const std::exception& e) {
        std::cerr << "list-versions error: " << e.what() << "\n";
        exit(1);
    }
}

static void cmd_get_version_metadata(const Args& args) {
    std::string bundleID   = get(args, "bundle-id",           "b");
    std::string appIDStr   = get(args, "app-id",              "i");
    std::string versionID  = get(args, "external-version-id", "");
    std::string passphrase = get(args, "keychain-passphrase", "");

    if (bundleID.empty() && appIDStr.empty()) {
        std::cerr << "Usage: ipatool get-version-metadata (-b BUNDLE_ID | -i APP_ID) --external-version-id ID\n";
        exit(1);
    }
    if (versionID.empty()) {
        std::cerr << "Error: --external-version-id is required\n";
        exit(1);
    }

    Account acc;
    if (!load_account(acc, passphrase)) { std::cerr << "Not logged in.\n"; exit(1); }

    AppStore store(COOKIE_FILE);
    if (get(args, "debug") == "true") store.set_debug(true);
    try {
        App app;
        if (!bundleID.empty()) {
            app = store.lookup(acc, bundleID);
        } else {
            app.id = std::stoll(appIDStr);
        }

        auto out = store.get_version_metadata(acc, app, versionID);

        json j;
        j["externalVersionID"] = versionID;
        j["displayVersion"]    = out.displayVersion;
        j["releaseDate"]       = out.releaseDate;
        j["success"]           = true;
        log_output(j);
    } catch (const std::exception& e) {
        std::cerr << "get-version-metadata error: " << e.what() << "\n";
        exit(1);
    }
}

static void cmd_revoke(const Args& args) {
    if (!std::ifstream(ACCOUNT_FILE).good()) {
        std::cerr << "Not logged in.\n";
        exit(1);
    }
    if (std::remove(ACCOUNT_FILE.c_str()) != 0) {
        std::cerr << "Error: failed to remove account file: " << ACCOUNT_FILE << "\n";
        exit(1);
    }
    std::remove(COOKIE_FILE.c_str()); // best-effort, ignore error
    json out;
    out["success"] = true;
    log_output(out);
}

static void cmd_download(const Args& args) {
    std::string bundleID       = get(args, "bundle-id",           "b");
    std::string appIDStr       = get(args, "app-id",              "i");
    std::string outputPath     = get(args, "output",              "o");
    std::string versionID      = get(args, "external-version-id", "");
    std::string passphrase     = get(args, "keychain-passphrase", "");
    bool        acquireLicense = (get(args, "purchase") == "true");

    if (bundleID.empty() && appIDStr.empty()) {
        std::cerr << "Usage: ipatool download (-b BUNDLE_ID | -i APP_ID) [-o OUTPUT_PATH] [--external-version-id ID] [--purchase]\n";
        exit(1);
    }

    Account acc;
    if (!load_account(acc, passphrase)) {
        std::cerr << "Not logged in.\n";
        exit(1);
    }

    AppStore store(COOKIE_FILE);
    if (get(args, "debug") == "true") store.set_debug(true);

    App app;

    // ── Progress bar ──────────────────────────────────────────────────────────
    // Format: "Downloading:  12% |████░░░░░░| (14/119 MB, 5.6 MB/s)"
    auto   lastDraw  = std::chrono::steady_clock::now() - std::chrono::milliseconds(200);
    auto   startTime = std::chrono::steady_clock::now();
    bool   isTTY     = use_color();
    int    prevDrawnCols = 0; // track columns written last tick for erase-on-shrink

#ifdef _WIN32
    HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);

    WORD defaultAttrs = s_defaultAttrs;
    {
        CONSOLE_SCREEN_BUFFER_INFO csbi_init;
        if (GetConsoleScreenBufferInfo(hErr, &csbi_init))
            defaultAttrs = csbi_init.wAttributes;
    }
    // attrFilled: swap foreground and background of the original console colors.
    // bits 0-3 = foreground, bits 4-7 = background (BACKGROUND_* = FOREGROUND_* << 4)
    // Take the original fg bits and shift them to bg, original bg bits shift to fg.
    const WORD origFG     = (defaultAttrs & 0x000F);
    const WORD origBG     = (defaultAttrs & 0x00F0);
    const WORD attrFilled = (WORD)((origFG << 4) | (origBG >> 4));

    if (isTTY) {
        CONSOLE_CURSOR_INFO cci;
        GetConsoleCursorInfo(hErr, &cci);
        cci.bVisible = FALSE;
        SetConsoleCursorInfo(hErr, &cci);
        // Restore cursor on any exit path
        signal(SIGINT,  signal_handler);
        signal(SIGTERM, signal_handler);
        atexit(restore_cursor);
    }
#endif

    ProgressCb progress = [&](int64_t received, int64_t total) {
        if (!isTTY) return;
        auto now     = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastDraw).count();
        bool done    = (total > 0 && received >= total);
        if (!done && elapsed < 65) return;
        lastDraw = now;

        double secs  = std::chrono::duration<double>(now - startTime).count();
        double speed = secs > 0.1 ? (received / 1048576.0) / secs : 0.0;

        auto fmt_mb = [](int64_t b) -> std::string {
            char buf[32];
            if (b >= 1024LL*1024*1024) snprintf(buf, sizeof(buf), "%.2f GB", b / 1073741824.0);
            else                        snprintf(buf, sizeof(buf), "%lld MB", (long long)(b / 1048576));
            return buf;
        };

        char pctStr[8] = "  0%";
        if (total > 0) {
            int pct = (int)(received * 100 / total);
            if (pct > 100) pct = 100;
            snprintf(pctStr, sizeof(pctStr), "%3d%%", pct);
        }

        char suffix[64];
        if (total > 0)
            snprintf(suffix, sizeof(suffix), "(%s/%s, %.1f MB/s)",
                fmt_mb(received).c_str(), fmt_mb(total).c_str(), speed);
        else
            snprintf(suffix, sizeof(suffix), "(%s, %.1f MB/s)",
                fmt_mb(received).c_str(), speed);

        std::string prefix  = std::string("Downloading: ") + pctStr + " |";
        std::string postfix = std::string("| ") + suffix;

        const int barW = 20;
        int filled = (total > 0) ? (int)((double)received / total * barW) : 0;
        if (filled > barW) filled = barW;

#ifdef _WIN32
        // Get current cursor row — we always park it at {0,row} after each tick
        CONSOLE_SCREEN_BUFFER_INFO csbi2;
        if (!GetConsoleScreenBufferInfo(hErr, &csbi2)) return;
        SHORT row  = csbi2.dwCursorPosition.Y;
        int   bufW = csbi2.dwSize.X;

        // Build the entire line as a CHAR_INFO array and write it in one call.
        // WriteConsoleOutputA writes directly to screen buffer cells — it never
        // moves the cursor, never wraps, never scrolls, regardless of line length.
        int lineW = (int)prefix.size() + barW + (int)postfix.size();
        int writeW = std::min(lineW, bufW); // clamp to buffer width
        // Also cover any extra cols from the previous (possibly wider) frame
        int totalW = std::max(writeW, prevDrawnCols);
        totalW = std::min(totalW, bufW);

        std::vector<CHAR_INFO> cells(totalW);
        // Fill everything with spaces at default attrs first (erases previous frame)
        for (int i = 0; i < totalW; i++) {
            cells[i].Char.AsciiChar = ' ';
            cells[i].Attributes     = defaultAttrs;
        }
        // Write prefix
        int col = 0;
        for (char c : prefix) {
            if (col >= writeW) break;
            cells[col].Char.AsciiChar = c;
            cells[col].Attributes     = defaultAttrs;
            col++;
        }
        // Write filled bar (white background)
        for (int i = 0; i < filled && col < writeW; i++, col++) {
            cells[col].Char.AsciiChar = ' ';
            cells[col].Attributes     = attrFilled;
        }
        // Write empty bar
        for (int i = filled; i < barW && col < writeW; i++, col++) {
            cells[col].Char.AsciiChar = ' ';
            cells[col].Attributes     = defaultAttrs;
        }
        // Write postfix
        for (char c : postfix) {
            if (col >= writeW) break;
            cells[col].Char.AsciiChar = c;
            cells[col].Attributes     = defaultAttrs;
            col++;
        }

        COORD  bufSize  = { (SHORT)totalW, 1 };
        COORD  bufCoord = { 0, 0 };
        SMALL_RECT region = { 0, row, (SHORT)(totalW - 1), row };
        WriteConsoleOutputA(hErr, cells.data(), bufSize, bufCoord, &region);

        prevDrawnCols = writeW;

        if (done) {
            for (auto& c : cells) { c.Char.AsciiChar = ' '; c.Attributes = defaultAttrs; }
            WriteConsoleOutputA(hErr, cells.data(), bufSize, bufCoord, &region);
            CONSOLE_CURSOR_INFO cci;
            GetConsoleCursorInfo(hErr, &cci);
            cci.bVisible = TRUE;
            SetConsoleCursorInfo(hErr, &cci);
        }
#else
        std::string bar;
        bar.reserve(barW * 3);
        for (int i = 0; i < filled;    i++) { bar += "\xe2\x96\x88"; } // █
        for (int i = filled; i < barW; i++) { bar += "\xe2\x96\x91"; } // ░

        std::cerr << "\r" << prefix << bar << postfix << std::flush;
        if (done) {
            int totalW = (int)prefix.size() + barW + (int)postfix.size();
            std::cerr << "\r" << std::string(totalW, ' ') << "\r" << std::flush;
        }
#endif
    };

    try {
        if (!bundleID.empty()) {
            app = store.lookup(acc, bundleID);
        } else {
            app.id = std::stoll(appIDStr);
        }

        auto out = store.download(acc, app, outputPath, versionID, progress);
        json dlOut;
        dlOut["output"]    = out.destinationPath;
        dlOut["purchased"] = false;
        dlOut["success"]   = true;
        log_output(dlOut);
    } catch (const LicenseRequired&) {
        if (!acquireLicense) {
            print_red_err("Error: you must purchase this app first.\n");
            if (!bundleID.empty())
                print_red_err("Run: ipatool purchase -b " + bundleID + "\n");
            else
                print_red_err("Run: ipatool search to find the bundle ID, then: ipatool purchase -b BUNDLE_ID\n");
            print_red_err("Or re-run with --purchase to acquire the license automatically.\n");
            exit(1);
        }
        // --purchase flag: acquire license then retry download once
        try {
            store.purchase(acc, app);
        } catch (const PasswordTokenExpired&) {
            if (!silent_relogin(acc, passphrase)) {
                print_red_err("Error: session expired. Please log in again.\n");
                exit(1);
            }
            try { store.purchase(acc, app); }
            catch (const std::exception& pe) {
                print_red_err(std::string("Purchase error: ") + pe.what() + "\n");
                exit(1);
            }
        } catch (const std::exception& pe) {
            print_red_err(std::string("Purchase error: ") + pe.what() + "\n");
            exit(1);
        }
        // Reset progress bar timing for the retry
        lastDraw      = std::chrono::steady_clock::now() - std::chrono::milliseconds(200);
        startTime     = std::chrono::steady_clock::now();
        prevDrawnCols = 0;
        try {
            auto out = store.download(acc, app, outputPath, versionID, progress);
            json dlOut;
            dlOut["output"]    = out.destinationPath;
            dlOut["purchased"] = true;
            dlOut["success"]   = true;
            log_output(dlOut);
        } catch (const PasswordTokenExpired&) {
            if (!silent_relogin(acc, passphrase)) {
                print_red_err("Error: session expired. Please log in again.\n");
                exit(1);
            }
            lastDraw      = std::chrono::steady_clock::now() - std::chrono::milliseconds(200);
            startTime     = std::chrono::steady_clock::now();
            prevDrawnCols = 0;
            try {
                auto out = store.download(acc, app, outputPath, versionID, progress);
                json dlOut;
                dlOut["output"]    = out.destinationPath;
                dlOut["purchased"] = true;
                dlOut["success"]   = true;
                log_output(dlOut);
            } catch (const std::exception& e2) {
                print_red_err(std::string("Download error: ") + e2.what() + "\n");
                exit(1);
            }
        } catch (const std::exception& e2) {
            print_red_err(std::string("Download error: ") + e2.what() + "\n");
            exit(1);
        }
    } catch (const PasswordTokenExpired&) {
        if (!silent_relogin(acc, passphrase)) {
            print_red_err("Error: session expired. Please log in again.\n");
            exit(1);
        }
        // Re-login succeeded — retry the entire operation once with fresh token
        try {
            if (!bundleID.empty()) app = store.lookup(acc, bundleID);
            lastDraw      = std::chrono::steady_clock::now() - std::chrono::milliseconds(200);
            startTime     = std::chrono::steady_clock::now();
            prevDrawnCols = 0;
            auto out = store.download(acc, app, outputPath, versionID, progress);
            json dlOut;
            dlOut["output"]    = out.destinationPath;
            dlOut["purchased"] = false;
            dlOut["success"]   = true;
            log_output(dlOut);
        } catch (const std::exception& e2) {
            print_red_err(std::string("Download error: ") + e2.what() + "\n");
            exit(1);
        }
    } catch (const std::exception& e) {
        print_red_err(std::string("Download error: ") + e.what() + "\n");
        exit(1);
    }
}

// ── Help ──────────────────────────────────────────────────────────────────────

static void print_help() {
    std::cout << R"(
ipatool-cpp — CLI tool to interact with the Apple App Store

Usage:
  ipatool [--keychain-passphrase PASSPHRASE] <command> [flags]

Commands:
  auth login            Authenticate with Apple ID
  auth info             Show saved account info
  auth revoke           Revoke and delete saved credentials
  search                Search for apps
  purchase              Acquire a free app license
  download              Download an app IPA
  list-versions         List available versions of an app
  get-version-metadata  Get metadata for a specific app version

Global flags:
  --format                Output format: "text" (default) or "json"
  --keychain-passphrase   Passphrase to encrypt/decrypt the saved account file.
                          When set on login, credentials are stored encrypted.
                          Required on all subsequent commands if login used it.

Examples:
  ipatool auth login                                          (interactive: prompts for email, password, 2FA)
  ipatool auth login -e user@example.com -p mypassword
  ipatool auth login -e user@example.com -p mypassword --keychain-passphrase mysecret
  ipatool auth login -e user@example.com -p mypassword --auth-code 123456
  ipatool search "angry birds" -l 5 --keychain-passphrase mysecret
  ipatool purchase -b com.example.app
  ipatool download -b com.example.app -o ./MyApp.ipa
  ipatool download -i 1234567890 -o ./MyApp.ipa

Flags per command:
  auth login:           -e/--email  -p/--password  -a/--auth-code  --keychain-passphrase
  search:               <term>  -l/--limit  --keychain-passphrase
  purchase:             -b/--bundle-id             --keychain-passphrase
  download:             -b/--bundle-id | -i/--app-id   -o/--output  --external-version-id  --purchase  --keychain-passphrase
  list-versions:        -b/--bundle-id | -i/--app-id   --keychain-passphrase
  get-version-metadata: -b/--bundle-id | -i/--app-id   --external-version-id  --keychain-passphrase
)";}


// ── main ──────────────────────────────────────────────────────────────────────


int main(int argc, char** argv) {
    init_color();
    if (argc < 2) { print_help(); return 0; }

    Args args = parse_args(argc, argv);
    g_format = get(args, "format", "", "text");
    if (g_format != "text" && g_format != "json") {
        std::cerr << "Error: invalid format \''" << g_format << "\'' — use \'text\' or \'json\'\n";
        return 1;
    }

    // Store passphrase for in-memory encryption — machine_id derived fresh each call
    std::string passphrase = get(args, "keychain-passphrase", "");
    init_mem_passphrase(passphrase);
    atexit(wipe_mem_passphrase);

    // Determine subcommand from leading positionals only (not app arguments)
    // e.g. ["auth", "login", ...] -> "auth login"
    //      ["search", "Minecraft", ...] -> "search"  (rest are args)
    std::string cmd;
    if (!args.pos.empty()) {
        cmd = args.pos[0];
        // Two-word commands: "auth login", "auth info", "auth revoke"
        if (cmd == "auth" && args.pos.size() >= 2)
            cmd = "auth " + args.pos[1];
    }

    if (cmd == "auth info" || cmd == "account") {
        cmd_show_account(args);
    } else if (cmd == "auth login" || cmd == "login") {
        cmd_login(args);
    } else if (cmd == "auth revoke" || cmd == "revoke") {
        cmd_revoke(args);
    } else if (cmd == "search") {
        cmd_search(args);
    } else if (cmd == "list-versions") {
        cmd_list_versions(args);
    } else if (cmd == "get-version-metadata") {
        cmd_get_version_metadata(args);
    } else if (cmd == "purchase") {
        cmd_purchase(args);
    } else if (cmd == "download") {
        cmd_download(args);
    } else if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        print_help();
    } else {
        std::cerr << "Unknown command: " << cmd << "\n";
        print_help();
        return 1;
    }

    return 0;
}
