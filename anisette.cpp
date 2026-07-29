#include "anisette.h"
#include "ipatool.h"
#include <nlohmann/json.hpp>
#include <sstream>
#include <cstdio>
#include <ctime>
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <shlobj.h>
#  include <filesystem>
#include <iostream>
#include <string>
#include <map>
#include <ctime>
#include <cstdio>
   namespace fs = std::filesystem;
#else
#  include <unistd.h>
#endif

// ============================================================================
//  Helpers
// ============================================================================

std::string AnisetteData::trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

// ============================================================================
//  from_server_output  — parse "Key: Value" stdout from a local anisette binary
// ============================================================================
AnisetteData AnisetteData::from_server_output(const std::string& output)
{
    AnisetteData a;
    std::istringstream ss(output);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = trim(line.substr(0, colon));
        std::string val = trim(line.substr(colon + 1));
        if      (key == "X-Apple-I-MD")         a.otp           = val;
        else if (key == "X-Apple-I-MD-M")        a.machineID     = val;
        else if (key == "X-Apple-I-MD-LU")       a.localUserUUID = val;
        else if (key == "X-Apple-I-MD-RINFO")    a.routingInfo   = val;
        else if (key == "X-Apple-I-SRL-NO")      a.serialNo      = val;
        else if (key == "X-Apple-I-Client-Time") a.clientTime    = val;
        else if (key == "X-Apple-Locale")        a.locale        = val;
        else if (key == "X-Apple-I-TimeZone")    a.timezone      = val;
        else if (key == "X-MMe-Client-Info")     a.clientInfo    = val;
        else if (key == "X-Mme-Device-Id")       a.deviceID      = val;
    }
    return a;
}

// ============================================================================
//  fetch_from_exe  — run a local anisette binary and return parsed data
// ============================================================================
AnisetteData AnisetteData::fetch_from_exe(const std::string& exe_path)
{
#ifdef _WIN32
    // 2>&1 to capture stderr — lets us see the error message if the binary fails
    std::string cmd = "\"" + exe_path + "\" 2>&1";
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen((exe_path + " 2>&1").c_str(), "r");
#endif
    if (!pipe)
        throw IpaError("anisette: could not run '" + exe_path + "'");

    std::string output;
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe))
        output += buf;

#ifdef _WIN32
    int rc = _pclose(pipe);
#else
    int rc = pclose(pipe);
#endif
    if (rc != 0) {
        const bool not_found = (rc == 9009)
            || output.find("not recognized") != std::string::npos
            || output.find("No such file")   != std::string::npos;
        if (not_found)
            throw IpaError("anisette binary not found: " + exe_path);
        // Include binary output in the error so we can see why it failed
        std::string detail = output;
        while (!detail.empty() && (detail.back() == '\n' || detail.back() == '\r'))
            detail.pop_back();
        throw IpaError("anisette exited with code " + std::to_string(rc)
                       + (detail.empty() ? "" : "\n" + detail));
    }

    AnisetteData a = from_server_output(output);
    if (!a.is_complete())
        throw IpaError("anisette: output missing X-Apple-I-MD or X-Apple-I-MD-M");
    // External binary (anisette.exe) — use legacy iTunes UA for Win7 compatibility
    if (a.userAgent.empty())
        a.userAgent = "iTunes/12.11.3 (Windows; Microsoft Windows 10 x64 "
                      "Professional Edition (Build 19041); x64) AppleWebKit/7611.3.10.1.16";
    return a;
}

// ============================================================================
//  from_json / fetch_from_public_servers
// ============================================================================
AnisetteData AnisetteData::from_json(const std::string& json_text)
{
    AnisetteData a;
    nlohmann::json j = nlohmann::json::parse(json_text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return a;
    auto get = [&](const char* key) -> std::string {
        auto it = j.find(key);
        return (it != j.end() && it->is_string()) ? it->get<std::string>() : "";
    };
    a.otp           = get("X-Apple-I-MD");
    a.machineID     = get("X-Apple-I-MD-M");
    a.localUserUUID = get("X-Apple-I-MD-LU");
    a.routingInfo   = get("X-Apple-I-MD-RINFO");
    a.serialNo      = get("X-Apple-I-SRL-NO");
    a.clientTime    = get("X-Apple-I-Client-Time");
    a.clientInfo    = get("X-MMe-Client-Info");
    a.deviceID      = get("X-Mme-Device-Id");
    std::string loc = get("X-Apple-Locale");
    std::string tz  = get("X-Apple-I-TimeZone");
    if (!loc.empty()) a.locale   = loc;
    if (!tz.empty())  a.timezone = tz;
    return a;
}

AnisetteData AnisetteData::fetch_from_public_servers(HttpClient& http, bool debug)
{
    static const char* SERVERS[] = {
        "https://ani.sidestore.io",
        "https://ani.f1sh.me",
        "https://ani.npeg.us",
        "https://ani.sidestore.app",
        "https://ani.846969.xyz",
        "https://anisette.wedotstud.io",
        "https://ani.neoarz.com",
        "https://ani3server.fly.dev",
        "https://ani.jaydenha.uk",
        "https://anisette.crystall1ne.dev",
    };
    std::string lastErr;
    for (int pass = 0; pass < 2; pass++) {
        for (const char* server : SERVERS) {
            try {
                HttpResponse res = http.get(server, {{"Accept", "application/json"}});
                if (debug)
                    fprintf(stderr, "[anisette] %s → HTTP %d\n", server, res.statusCode);
                if (res.statusCode != 200) {
                    lastErr = std::string(server) + ": HTTP " + std::to_string(res.statusCode);
                    continue;
                }
                AnisetteData a = from_json(res.body);
                if (a.is_complete()) return a;
                lastErr = std::string(server) + ": missing required fields";
            } catch (const std::exception& e) {
                lastErr = std::string(server) + ": " + e.what();
            }
        }
        if (pass == 0) {
#ifdef _WIN32
            Sleep(700);
#else
            usleep(700 * 1000);
#endif
        }
    }
    throw IpaError("anisette: all public servers failed — " + lastErr);
}

// ============================================================================
//  generate_locally  — native anisette generation via MS Store iCloud (Windows only)
//
//  Loads AOSKit.dll from the cached MS Store iCloud package and calls
//  copyOTPHeadersForDSID directly via known offsets.
//
//  The DLL cache is populated once on first run and NOT invalidated on
//  iCloud updates — this is intentional so the offsets remain valid.
//  If things break (very rare), the user can delete the cache folder manually.
//
//  adi.pb is NOT cached — iCloud manages it automatically (reprovisioning).
//
//  Offsets relative to AOSRegisterClientInfo (AOSKit 15.9.60.0 = version 133.3):
//    copyOTPHeadersForDSID  +0x115E0
//    _GetDeviceId           +0x134E0
//    _GetLocalUserUUID      +0x12EC0
//    _GetClientInfoOS       +0x161B0
//    _GetClientInfoModel    +0x163C0
// ============================================================================

#ifdef _WIN32

// ── CoreFoundation function types ────────────────────────────────────────────
using CFStringCreateFn      = void*(__cdecl*)(void*, const char*, unsigned int);
using CFStringGetCStringFn  = bool (__cdecl*)(void*, char*, long long, unsigned int);
using CFStringGetLengthFn   = long long(__cdecl*)(void*);
using CFDictionaryGetValueFn= void*(__cdecl*)(void*, void*);
using CFReleaseFn           = void (__cdecl*)(void*);

// ── AOSKit function types ─────────────────────────────────────────────────────
using AOSRegisterClientInfoFn = int(__cdecl*)(const char*, const char*,
                                               const char*, const char*);
using CopyOTPHeadersFn  = void*(__fastcall*)(void* dsid);
using GetRawStrFn       = const char*(__fastcall*)();

static constexpr unsigned int kCFStringEncodingUTF8 = 0x08000100;

// ── Offsets (AOSKit 15.9.60.0 / AOSKitWin 133.3) ────────────────────────────
static constexpr ptrdiff_t OFS_COPY_OTP        = 0x115E0;
static constexpr ptrdiff_t OFS_GET_DEVICE_ID   = 0x134E0;
static constexpr ptrdiff_t OFS_GET_LOCAL_UUID  = 0x12EC0;
static constexpr ptrdiff_t OFS_CLIENT_INFO_OS  = 0x161B0;
static constexpr ptrdiff_t OFS_CLIENT_INFO_MDL = 0x163C0;

// ── Helpers ──────────────────────────────────────────────────────────────────

static std::string path_slash(const fs::path& p) {
    std::string s = p.string();
    if (!s.empty() && s.back() != '\\') s += '\\';
    return s;
}

static bool ani_reg_set(HKEY root, const char* subkey,
                        const char* name, const std::string& val) {
    HKEY key = nullptr;
    if (RegCreateKeyExA(root, subkey, 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return false;
    LONG rc = RegSetValueExA(key, name, 0, REG_SZ,
                             (const BYTE*)val.c_str(), (DWORD)(val.size()+1));
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

// ── Locate MS Store iCloud in WindowsApps ────────────────────────────────────
static bool find_icloud_dir(fs::path& out) {
    const fs::path root = "C:/Program Files/WindowsApps";
    if (!fs::exists(root)) return false;
    fs::path best;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(root, ec)) {
        if (!entry.is_directory()) continue;
        const auto name = entry.path().filename().string();
        if (name.rfind("AppleInc.iCloud_", 0) != 0) continue;
        const fs::path icloud = entry.path() / "iCloud";
        if (fs::exists(icloud / "AOSKit.dll")) {
            if (best.empty() || name > best.parent_path().filename().string())
                best = icloud;
        }
    }
    if (best.empty()) return false;
    out = best;
    return true;
}

// ── DLL cache ────────────────────────────────────────────────────────────────
// Populated once; not invalidated on iCloud updates.
// Intentional — offsets are pinned to a specific AOSKit version.
static fs::path get_cache_dir(const fs::path& icloud_dir) {
    wchar_t buf[MAX_PATH]{};
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, buf);
    return fs::path(buf) / "IPA_Downloader" / "anisette-cache"
           / icloud_dir.parent_path().filename().string();
}

static bool ensure_cache(const fs::path& src, const fs::path& cache) {
    // Cache already populated — use as-is, no version check
    if (fs::exists(cache / "AOSKit.dll")) return true;

    std::error_code ec;
    fs::create_directories(cache, ec);
    for (const auto& entry : fs::directory_iterator(src, ec)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".dll") continue;
        fs::copy_file(entry.path(), cache / entry.path().filename(),
                      fs::copy_options::overwrite_existing, ec);
    }
    return fs::exists(cache / "AOSKit.dll");
}

// ── Locate adi.pb ────────────────────────────────────────────────────────────
static bool find_adi_pb(std::string& adi_dir) {
    // Classic path (iTunes / legacy iCloud x86)
    const char* classic = "C:\\ProgramData\\Apple Computer\\iTunes\\adi";
    if (fs::exists(fs::path(classic) / "adi.pb")) {
        adi_dir = classic; return true;
    }
    // MS Store iCloud — AppData\Local
    wchar_t buf[MAX_PATH]{};
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, buf);
    fs::path p2 = fs::path(buf) / "Apple" / "Internet Services" / "adi";
    if (fs::exists(p2 / "adi.pb")) { adi_dir = p2.string(); return true; }
    // AppData\Roaming
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, buf);
    fs::path p3 = fs::path(buf) / "Apple Computer" / "iTunes" / "adi";
    if (fs::exists(p3 / "adi.pb")) { adi_dir = p3.string(); return true; }
    return false;
}

// ── Registry setup for CoreADI ───────────────────────────────────────────────
static void setup_registry(const fs::path& dll_dir, const std::string& adi_dir) {
    const std::string install = path_slash(dll_dir);
    // HKCU — required, always accessible without admin rights
    ani_reg_set(HKEY_CURRENT_USER, "SOFTWARE\\Apple Inc.\\Apple Application Support",
                "InstallDir", install);
    ani_reg_set(HKEY_CURRENT_USER, "SOFTWARE\\Apple Inc.\\Internet Services",
                "InstallDir", install);
    ani_reg_set(HKEY_CURRENT_USER, "SOFTWARE\\Apple Inc.\\CoreADI", "ADIPath", adi_dir);
    // HKLM — optional, requires admin rights
    ani_reg_set(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Apple Inc.\\Apple Application Support",
                "InstallDir", install);
    ani_reg_set(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Apple Inc.\\Internet Services",
                "InstallDir", install);
    ani_reg_set(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Apple Inc.\\CoreADI", "ADIPath", adi_dir);
}

// ── CFString → std::string ───────────────────────────────────────────────────
static std::string cf_to_str(void* cfstr,
                              CFStringGetLengthFn  pfnLen,
                              CFStringGetCStringFn pfnGet) {
    if (!cfstr || !pfnLen || !pfnGet) return "";
    if (pfnLen(cfstr) == 0) return "";
    char buf[2048]{};
    return pfnGet(cfstr, buf, sizeof(buf), kCFStringEncodingUTF8) ? buf : "";
}

static void print_winerr(const char* ctx) {
    char buf[512]{};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, GetLastError(), 0, buf, sizeof(buf), nullptr);
    std::cerr << ctx << ": " << buf;
}

// ── generate_locally ─────────────────────────────────────────────────────────
AnisetteData AnisetteData::generate_locally()
{
    // 1. Locate MS Store iCloud
    fs::path icloud_dir;
    if (!find_icloud_dir(icloud_dir))
        throw IpaError("anisette: MS Store iCloud not found — "
                       "install iCloud from Microsoft Store");

    // 2. Prepare DLL cache
    const fs::path cache = get_cache_dir(icloud_dir);
    if (!ensure_cache(icloud_dir, cache))
        throw IpaError("anisette: failed to prepare DLL cache");

    // 3. Find adi.pb (created by iCloud on first Apple ID sign-in)
    std::string adi_dir;
    if (!find_adi_pb(adi_dir))
        throw IpaError("anisette: adi.pb not found — "
                       "sign in to iCloud (MS Store) with your Apple ID first");

    // 4. Registry entries for CoreADI
    setup_registry(cache, adi_dir);

    // 5. Load DLLs from cache
    //    WindowsApps is protected by Package Identity enforcement — LoadLibrary
    //    from it crashes for non-UWP processes. Cache is the only option.
    if (!SetDllDirectoryW(cache.c_str()))
        throw IpaError("anisette: SetDllDirectory failed");
    SetCurrentDirectoryW(cache.c_str());

    auto load = [&](const wchar_t* name) -> HINSTANCE {
        HINSTANCE h = LoadLibraryW(name);
        if (!h) {
            std::wcerr << L"Failed to load " << name << L"\n";
            print_winerr("");
        }
        return h;
        };

    load(L"CoreFoundation.dll");
    load(L"CoreADI64.dll");
    load(L"objc.dll");
    load(L"Foundation.dll");
    LoadLibraryW(L"libdispatch.dll");   // optional
    LoadLibraryW(L"CFNetwork.dll");

    HINSTANCE aplzod = LoadLibraryW(L"APLZOD6432.dll");

    if (aplzod) {
        using MSProviderInitFn = int(__cdecl*)();
        auto msInit = (MSProviderInitFn)GetProcAddress(aplzod, "MSProviderInit");
        if (msInit) msInit();
    }

    HINSTANCE aosKit = load(L"AOSKit.dll");

    // Register client info
    auto aosReg = (AOSRegisterClientInfoFn)
                   GetProcAddress(aosKit, "AOSRegisterClientInfo");
    if (aosReg) aosReg("com.apple.iCloud", "15.8", "com.apple.AuthKitWin", "1");

    // 6. Resolve function pointers via offsets from AOSRegisterClientInfo
    uintptr_t anchor = (uintptr_t)GetProcAddress(aosKit, "AOSRegisterClientInfo");
    if (!anchor)
        throw IpaError("anisette: AOSRegisterClientInfo not found in AOSKit.dll");

    auto pfnCopyOTP    = (CopyOTPHeadersFn)(anchor + OFS_COPY_OTP);
    auto pfnGetDevice  = (GetRawStrFn)     (anchor + OFS_GET_DEVICE_ID);
    auto pfnGetUUID    = (GetRawStrFn)     (anchor + OFS_GET_LOCAL_UUID);
    auto pfnClientOS   = (GetRawStrFn)     (anchor + OFS_CLIENT_INFO_OS);
    auto pfnClientMdl  = (GetRawStrFn)     (anchor + OFS_CLIENT_INFO_MDL);

    // Dictionary keys
    void** pKeyMD_M = (void**)GetProcAddress(aosKit, "kAOSMDMachineIdHeaderName");
    void** pKeyMD   = (void**)GetProcAddress(aosKit, "kAOSMDOneTimePasswordHeaderName");
    if (!pKeyMD_M || !pKeyMD)
        throw IpaError("anisette: AOSKit MD keys not found");

    // CoreFoundation functions
    HINSTANCE cf = GetModuleHandleW(L"CoreFoundation.dll");
    if (!cf) throw IpaError("anisette: CoreFoundation.dll not loaded");

    auto pfnCFCreate = (CFStringCreateFn)
                        GetProcAddress(cf, "CFStringCreateWithCString");
    auto pfnCFGetLen = (CFStringGetLengthFn)
                        GetProcAddress(cf, "CFStringGetLength");
    auto pfnCFGetStr = (CFStringGetCStringFn)
                        GetProcAddress(cf, "CFStringGetCString");
    auto pfnCFDictGet= (CFDictionaryGetValueFn)
                        GetProcAddress(cf, "CFDictionaryGetValue");
    auto pfnCFRelease= (CFReleaseFn)
                        GetProcAddress(cf, "CFRelease");

    if (!pfnCFCreate || !pfnCFGetStr || !pfnCFDictGet || !pfnCFRelease)
        throw IpaError("anisette: CoreFoundation exports missing");

    // 7. Call copyOTPHeadersForDSID
    void* dict = nullptr;
    for (const char* dsid : { "-2", "-1" }) {
        void* dsidStr = pfnCFCreate(nullptr, dsid, kCFStringEncodingUTF8);
        if (!dsidStr) continue;
        dict = pfnCopyOTP(dsidStr);
        pfnCFRelease(dsidStr);
        if (dict) break;
    }
    if (!dict)
        throw IpaError("anisette: copyOTPHeadersForDSID returned null — "
                       "is iCloud running and signed in?");

    // 8. Extract MD and MD-M
    std::string md   = cf_to_str(pfnCFDictGet(dict, *pKeyMD),   pfnCFGetLen, pfnCFGetStr);
    std::string md_m = cf_to_str(pfnCFDictGet(dict, *pKeyMD_M), pfnCFGetLen, pfnCFGetStr);
    pfnCFRelease(dict);

    if (md.empty() || md_m.empty())
        throw IpaError("anisette: empty OTP/MachineID from AOSKit");

    // 9. Device ID, Local UUID, Client Info
    std::string deviceId, localUUID, clientInfo;

    const char* rawDevice = pfnGetDevice();
    if (rawDevice) deviceId = rawDevice;

    const char* rawUUID = pfnGetUUID();
    if (rawUUID) localUUID = rawUUID;

    const char* rawOS  = pfnClientOS();
    const char* rawMdl = pfnClientMdl();
    if (rawOS && rawMdl) {
        char buf[512]{};
        snprintf(buf, sizeof(buf), "<PC> <%s> <%s>", rawMdl, rawOS);
        clientInfo = buf;
    }

    // 10. Assemble AnisetteData
    AnisetteData a;
    a.otp           = md;
    a.machineID     = md_m;
    a.localUserUUID = localUUID;
    a.deviceID      = deviceId;
    // Hardcode Client-Info to match the GSA User-Agent (iTunes UA format).
    // The dynamic value from AOSKit contains "AOSKit/133.3 (iCloud/0.0)" which
    // does not match the iTunes UA used in GSA requests.
    a.clientInfo    = "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKitWin/1 (com.apple.iCloud/1)>";
    a.serialNo      = "C02LKHBBFD57";
    a.routingInfo   = "67437824";
    a.locale        = "en_US";
    a.timezone      = "PST";
    a.userAgent     = "iTunes/12.13.10 (Windows; Microsoft Windows 10 x64 "
                      "Professional Edition (Build 19045); x64) AppleWebKit/7613.3.9.0.2";
    // clientTime left empty — gsa.cpp fills it when building the request

    return a;
}

#else // !_WIN32

AnisetteData AnisetteData::generate_locally()
{
    throw IpaError("anisette: generate_locally() is only supported on Windows");
}

#endif // _WIN32
