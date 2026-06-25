#include "hwid.h"
#include "sha2.h"
#include <cstring>
#include <cstdio>

#ifdef _WIN32
#  include <windows.h>
#elif defined(__APPLE__)
#  include <CoreFoundation/CoreFoundation.h>
#  include <IOKit/IOKitLib.h>
#else
#  include <fstream>
#endif

// SHA-256 of input → lowercase hex string (shared across all platform branches)
static std::string sha256_hex(const std::string& input) {
    Bytes hash = sha2::digest(input);
    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + i*2, 3, "%02x", hash[i]);
    return std::string(hex, 64);
}

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

// Windows machine ID: SHA256(ProductId + MachineGuid)
std::string get_machine_id() {
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
    // kIOMasterPortDefault was renamed to kIOMainPortDefault in the macOS 12 SDK;
    // the old name still works but is deprecated and warns on every build.
    // __MAC_12_0 is only defined once AvailabilityMacros.h has been pulled in
    // (which IOKitLib.h above already does), so this check is safe here.
#if defined(__MAC_12_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_12_0
    const mach_port_t main_port = kIOMainPortDefault;
#else
    const mach_port_t main_port = kIOMasterPortDefault;
#endif
    io_service_t service = IOServiceGetMatchingService(
        main_port,
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

// macOS machine ID: SHA256(IOPlatformSerialNumber + IOPlatformUUID)
std::string get_machine_id() {
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

// Linux machine ID: SHA256(machine-id + product_uuid)
std::string get_machine_id() {
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

const char* FILE_KEY_SALT = "nice_token_is_nice";

bool derive_key_from_machine(const std::string& machine_id,
                             const std::string& passphrase,
                             const unsigned char* salt, int salt_len,
                             unsigned char* key_out) {
    // Mix FILE_KEY_SALT into the key material so the derivation is ipatool-specific
    std::string material = machine_id + FILE_KEY_SALT + passphrase;
    Bytes key = sha2::pbkdf2(material, salt, salt_len, 100000, 32);
    memcpy(key_out, key.data(), 32);
    return true;
}
