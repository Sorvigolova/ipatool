#include "device_mac.h"
#include "ipatool.h"   // IpaError

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <mutex>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2ipdef.h>
#  include <windows.h>
#  include <iphlpapi.h>   // GetIfTable2 / MIB_IF_ROW2 (netioapi.h)
#  include <cctype>
#  include <cwchar>
#elif defined(__APPLE__)
#  include <CoreFoundation/CoreFoundation.h>
#  include <IOKit/IOKitLib.h>
#else
#  include <filesystem>
#  include <fstream>
#endif

namespace {

bool g_debug = false;

struct Detected {
    std::vector<uint8_t> mac;
    std::string          source;
    std::string          error;   // non-empty when detection failed
};

void debug_log(const char* fmt, const std::string& a = {}, const std::string& b = {}) {
    if (!g_debug) return;
    fprintf(stderr, "[DEBUG] device ID: ");
    fprintf(stderr, fmt, a.c_str(), b.c_str());
    fputc('\n', stderr);
}

// ─────────────────────────────────────────────────────────────────────────────
#if defined(__APPLE__)

// IOKit property names are used as literals: CFSTR() only accepts string
// literals, and the kIOPrimaryInterface / kIOMACAddress macros from the
// IOKit/network headers do not expand to one in every SDK.

// Read IOMACAddress from the service itself or any of its parents
// (the address lives on the controller, the interface is its child).
bool iokit_mac_of(io_service_t svc, std::vector<uint8_t>& out) {
    CFTypeRef prop = IORegistryEntrySearchCFProperty(
        svc, kIOServicePlane, CFSTR("IOMACAddress"), kCFAllocatorDefault,
        kIORegistryIterateRecursively | kIORegistryIterateParents);
    if (!prop) return false;
    bool ok = false;
    if (CFGetTypeID(prop) == CFDataGetTypeID() && CFDataGetLength((CFDataRef)prop) == 6) {
        const UInt8* p = CFDataGetBytePtr((CFDataRef)prop);
        out.assign(p, p + 6);
        ok = true;
    }
    CFRelease(prop);
    return ok;
}

// First service matching `match` (consumed) that yields a valid MAC.
bool iokit_find(CFMutableDictionaryRef match, const char* what, Detected& d) {
    if (!match) return false;
    io_iterator_t it = IO_OBJECT_NULL;
    // MACH_PORT_NULL == default main port on every macOS version
    if (IOServiceGetMatchingServices(MACH_PORT_NULL, match, &it) != KERN_SUCCESS)
        return false;

    bool found = false;
    io_service_t svc;
    while (!found && (svc = IOIteratorNext(it)) != IO_OBJECT_NULL) {
        std::vector<uint8_t> mac;
        if (iokit_mac_of(svc, mac)) {
            if (!is_placeholder_mac(mac.data(), mac.size())) {
                d.mac    = std::move(mac);
                d.source = std::string("IOKit, ") + what;
                found    = true;
            }
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);
    return found;
}

Detected detect() {
    Detected d;

    // 1. Primary built-in interface: {IOPropertyMatch: {IOPrimaryInterface: true}}.
    //    Class-agnostic on purpose: on Apple Silicon the Wi-Fi en0 may not be an
    //    IOEthernetInterface subclass.
    {
        CFMutableDictionaryRef match = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        CFMutableDictionaryRef prop = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(prop, CFSTR("IOPrimaryInterface"), kCFBooleanTrue);
        CFDictionarySetValue(match, CFSTR("IOPropertyMatch"), prop);
        CFRelease(prop);
        if (iokit_find(match, "primary interface", d)) return d;
    }

    // 2. en0 by BSD name.
    if (iokit_find(IOBSDNameMatching(MACH_PORT_NULL, 0, "en0"), "fallback interface", d))
        return d;

    d.error = "IOKit reported no valid MAC address for the primary interface or en0";
    return d;
}

// ─────────────────────────────────────────────────────────────────────────────
#elif defined(_WIN32)

// PnP instance ID of a network adapter, e.g. "PCI\VEN_8086&..." or
// "USB\VID_0BDA&...". Read from the network class key by interface GUID.
std::string pnp_instance_id(const GUID& ifGuid) {
    wchar_t guidStr[64] = {};
    swprintf(guidStr, 64, L"{%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             (unsigned long)ifGuid.Data1, ifGuid.Data2, ifGuid.Data3,
             ifGuid.Data4[0], ifGuid.Data4[1], ifGuid.Data4[2], ifGuid.Data4[3],
             ifGuid.Data4[4], ifGuid.Data4[5], ifGuid.Data4[6], ifGuid.Data4[7]);
    std::wstring key = L"SYSTEM\\CurrentControlSet\\Control\\Network\\"
                       L"{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
    key += guidStr;
    key += L"\\Connection";

    wchar_t buf[512] = {};
    DWORD size = sizeof(buf);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, key.c_str(), L"PnPInstanceId",
                     RRF_RT_REG_SZ, nullptr, buf, &size) != ERROR_SUCCESS)
        return {};
    std::string out;
    for (const wchar_t* p = buf; *p; ++p) out += (*p < 0x80) ? (char)*p : '?';
    return out;
}

bool starts_with_ci(const std::string& s, const char* prefix) {
    size_t n = strlen(prefix);
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; ++i)
        if (toupper((unsigned char)s[i]) != toupper((unsigned char)prefix[i])) return false;
    return true;
}

Detected detect() {
    Detected d;
    PMIB_IF_TABLE2 table = nullptr;
    if (GetIfTable2(&table) != NO_ERROR || !table) {
        d.error = "GetIfTable2 failed";
        return d;
    }

    struct Candidate { int prio; std::vector<uint8_t> mac; std::string desc; };
    std::vector<Candidate> cands;

    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IF_ROW2& r = table->Table[i];

        // Physical adapters only — excludes Hyper-V, VPN/TAP, VirtualBox,
        // VMware, loopback, tunnels, WAN miniports, filter/LWF instances.
        if (!r.InterfaceAndOperStatusFlags.HardwareInterface) continue;
        if (r.InterfaceAndOperStatusFlags.FilterInterface)    continue;
        // Bluetooth PAN reports itself as Ethernet — not a network card.
        if (r.PhysicalMediumType == NdisPhysicalMediumBluetooth) continue;

        int prio;
        if      (r.Type == IF_TYPE_ETHERNET_CSMACD) prio = 0;   // wired
        else if (r.Type == IF_TYPE_IEEE80211)       prio = 1;   // Wi-Fi
        else continue;

        // Built-in (PCI / SoC) adapters before removable ones, so plugging a
        // USB dongle or a dock does not change the device ID.
        std::string pnp = pnp_instance_id(r.InterfaceGuid);
        if (starts_with_ci(pnp, "BTH")) continue;          // Bluetooth
        bool removable = starts_with_ci(pnp, "USB") || starts_with_ci(pnp, "SWD");
        if (removable) prio += 2;

        // Factory address first; current address only if the permanent one
        // is not reported. Current Wi-Fi addresses may be randomized.
        const UCHAR* addr = r.PermanentPhysicalAddress;
        ULONG        len  = r.PhysicalAddressLength;
        bool permanent    = (len == 6 && !is_placeholder_mac(addr, 6));
        if (!permanent) addr = r.PhysicalAddress;
        if (len != 6 || is_placeholder_mac(addr, 6)) continue;

        std::string desc = std::string(removable ? "removable " : "built-in ")
                         + ((prio % 2) == 0 ? "Ethernet" : "Wi-Fi")
                         + (permanent ? ", permanent address" : ", current address");
        cands.push_back({prio, std::vector<uint8_t>(addr, addr + 6), desc});
    }
    FreeMibTable(table);

    if (cands.empty()) {
        d.error = "no physical Ethernet or Wi-Fi adapter with a valid MAC address";
        return d;
    }

    // Deterministic: built-in before removable, wired before Wi-Fi, then
    // lowest MAC. Independent of enumeration order, adapter state and the
    // connected network.
    std::sort(cands.begin(), cands.end(), [](const Candidate& a, const Candidate& b) {
        return a.prio != b.prio ? a.prio < b.prio : a.mac < b.mac;
    });
    d.mac    = cands.front().mac;
    d.source = cands.front().desc;
    return d;
}

// ─────────────────────────────────────────────────────────────────────────────
#else // Linux and other POSIX

Detected detect() {
    namespace fs = std::filesystem;
    Detected d;

    struct Candidate { int prio; std::string name; std::vector<uint8_t> mac; };
    std::vector<Candidate> cands;

    std::error_code ec;
    for (const auto& e : fs::directory_iterator("/sys/class/net", ec)) {
        const fs::path p    = e.path();
        const std::string n = p.filename().string();
        // Physical adapters have a backing device; virtual ones (lo, docker0,
        // veth*, br*, tun*, wg*) do not.
        if (!fs::exists(p / "device", ec)) continue;

        std::ifstream f(p / "address");
        std::string s;
        if (!(f >> s)) continue;
        unsigned v[6];
        if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
            continue;
        std::vector<uint8_t> mac(6);
        for (int i = 0; i < 6; ++i) mac[i] = (uint8_t)v[i];
        if (is_placeholder_mac(mac.data(), 6)) continue;

        int prio = fs::exists(p / "wireless", ec) ? 1 : 0;   // wired first
        cands.push_back({prio, n, mac});
    }

    if (cands.empty()) {
        d.error = "no physical network adapter with a valid MAC address in /sys/class/net";
        return d;
    }
    std::sort(cands.begin(), cands.end(), [](const Candidate& a, const Candidate& b) {
        return a.prio != b.prio ? a.prio < b.prio : a.name < b.name;
    });
    d.mac    = cands.front().mac;
    d.source = cands.front().prio ? "wireless adapter" : "wired adapter";
    return d;
}

#endif

const Detected& detected() {
    static std::once_flag once;
    static Detected d;
    std::call_once(once, [] {
        d = detect();
        if (d.error.empty())
            debug_log("OK (%s)", d.source);
        else
            debug_log("FAILED (%s)", d.error);
    });
    return d;
}

} // namespace

bool is_placeholder_mac(const uint8_t* m, size_t len) {
    if (!m || len != 6) return true;
    static const uint8_t kApple02[6] = {0x02, 0, 0, 0, 0, 0};
    static const uint8_t kOldFallback[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    bool allZero = true, allFF = true;
    for (size_t i = 0; i < 6; ++i) {
        if (m[i] != 0x00) allZero = false;
        if (m[i] != 0xFF) allFF   = false;
    }
    if (allZero || allFF) return true;
    if (memcmp(m, kApple02, 6) == 0)     return true;
    if (memcmp(m, kOldFallback, 6) == 0) return true;
    if (m[0] & 0x01) return true;   // multicast bit — not a unicast hardware address
    return false;
}

std::vector<uint8_t> device_mac_address() {
    const Detected& d = detected();
    if (!d.error.empty())
        throw IpaError("could not determine this machine's network adapter MAC address ("
                       + d.error + "); refusing to contact Apple with a placeholder "
                       "device ID, which can get the Apple ID locked");
    return d.mac;
}

std::string device_guid() {
    std::vector<uint8_t> m = device_mac_address();
    std::string s;
    char b[3];
    for (uint8_t c : m) { snprintf(b, sizeof(b), "%02X", c); s += b; }
    return s;
}

std::string device_mac_source() {
    return detected().source;
}

void device_mac_set_debug(bool on) {
    g_debug = on;
}
