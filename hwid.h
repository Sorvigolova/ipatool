#pragma once
// hwid.h — Cross-platform machine ID derivation for account file encryption.
//
// Returns a stable, machine-bound identifier used as input to the file
// encryption key derivation: PBKDF2(machine_id + "nice_key_is_nice" + passphrase, ...)
// Also called fresh on every in-memory encrypt/decrypt via g_machine_id_fn.
//
// Windows : SHA256(ProductId + MachineGuid)
//           ProductId  — HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
//           MachineGuid — HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
//           Inspired by iTunes SC Info binding to the Windows product key.
// Linux   : SHA256(machine-id + product_uuid)
//           /etc/machine-id + /sys/class/dmi/id/product_uuid
// macOS   : SHA256(IOPlatformSerialNumber + IOPlatformUUID) via IOKit

#include <string>
#include <vector>
#include <cstring>
#include <openssl/evp.h>

#ifdef _WIN32
#  include <windows.h>
#elif defined(__APPLE__)
#  include <CoreFoundation/CoreFoundation.h>
#  include <IOKit/IOKitLib.h>
#else
#  include <fstream>
#endif

// ── Platform machine ID ───────────────────────────────────────────────────────

#ifdef _WIN32

static std::string reg_read_string(HKEY root, const char* path, const char* name) {
    HKEY key;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return "";
    char buf[256] = {};
    DWORD size = sizeof(buf);
    DWORD type = REG_SZ;
    RegQueryValueExA(key, name, nullptr, &type, (LPBYTE)buf, &size);
    RegCloseKey(key);
    return std::string(buf);
}

// Helper: SHA-256 of input → lowercase hex string, using EVP (OpenSSL 3 safe)
static std::string sha256_hex(const std::string& input) {
    unsigned char hash[32];
    unsigned int  len = 32;
    EVP_Digest(input.data(), input.size(), hash, &len, EVP_sha256(), nullptr);
    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + i*2, 3, "%02x", hash[i]);
    return std::string(hex, 64);
}

// Windows machine ID: SHA256(ProductId + MachineGuid)
static std::string get_machine_id() {
    std::string product_id  = reg_read_string(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "ProductId");
    std::string machine_guid = reg_read_string(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography",
        "MachineGuid");

    std::string combined = product_id + machine_guid;
    if (combined.empty()) return "fallback-windows";
    return sha256_hex(combined);
}

#elif defined(__APPLE__)

static std::string iokit_string(const char* key) {
    io_service_t service = IOServiceGetMatchingService(
        kIOMasterPortDefault,
        IOServiceMatching("IOPlatformExpertDevice"));
    if (!service) return "";

    CFStringRef cf_key = CFStringCreateWithCString(
        kCFAllocatorDefault, key, kCFStringEncodingUTF8);
    CFTypeRef cf_val = IORegistryEntryCreateCFProperty(
        service, cf_key, kCFAllocatorDefault, 0);
    CFRelease(cf_key);
    IOObjectRelease(service);

    if (!cf_val) return "";
    char buf[128] = {};
    CFStringGetCString((CFStringRef)cf_val, buf, sizeof(buf),
                       kCFStringEncodingUTF8);
    CFRelease(cf_val);
    return std::string(buf);
}

static std::string sha256_hex(const std::string& input) {
    unsigned char hash[32];
    unsigned int  len = 32;
    EVP_Digest(input.data(), input.size(), hash, &len, EVP_sha256(), nullptr);
    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + i*2, 3, "%02x", hash[i]);
    return std::string(hex, 64);
}

// macOS machine ID: SHA256(IOPlatformSerialNumber + IOPlatformUUID)
static std::string get_machine_id() {
    std::string serial = iokit_string("IOPlatformSerialNumber");
    std::string uuid   = iokit_string("IOPlatformUUID");

    std::string combined = serial + uuid;
    if (combined.empty()) return "fallback-macos";
    return sha256_hex(combined);
}

#else // Linux

static std::string read_file_first_line(const char* path) {
    std::ifstream f(path);
    if (!f) return "";
    std::string line;
    std::getline(f, line);
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r'
                              || line.back() == ' '))
        line.pop_back();
    return line;
}

static std::string sha256_hex(const std::string& input) {
    unsigned char hash[32];
    unsigned int  len = 32;
    EVP_Digest(input.data(), input.size(), hash, &len, EVP_sha256(), nullptr);
    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + i*2, 3, "%02x", hash[i]);
    return std::string(hex, 64);
}

// Linux machine ID: SHA256(machine-id + product_uuid)
static std::string get_machine_id() {
    std::string machine_id  = read_file_first_line("/etc/machine-id");
    if (machine_id.empty())
        machine_id = read_file_first_line("/var/lib/dbus/machine-id");
    std::string product_uuid = read_file_first_line(
        "/sys/class/dmi/id/product_uuid");

    std::string combined = machine_id + product_uuid;
    if (combined.empty()) return "fallback-linux";
    return sha256_hex(combined);
}

#endif

// ── HWID derivation ───────────────────────────────────────────────────────────

static const char* FILE_KEY_SALT = "nice_key_is_nice";
// Derive 32-byte file encryption key:
// PBKDF2-SHA256(machine_id + passphrase, random_salt, 100000, 32)
// FILE_KEY_SALT is mixed into the key material, random_salt is the PBKDF2 salt
static bool derive_key_from_machine(const std::string& machine_id,
                                     const std::string& passphrase,
                                     const unsigned char* salt, int salt_len,
                                     unsigned char* key_out) {
    // Mix FILE_KEY_SALT into the key material so the derivation is ipatool-specific
    std::string material = machine_id + FILE_KEY_SALT + passphrase;
    return PKCS5_PBKDF2_HMAC(
        material.c_str(), (int)material.size(),
        salt, salt_len,
        100000, EVP_sha256(),
        32, key_out) == 1;
}


