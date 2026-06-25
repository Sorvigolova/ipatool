#pragma once
// gsa.h — Grand Slam Authentication (GSA) for Apple ID
//
// Replaces the deprecated iTunes /auth/v1/native/fast endpoint.
//
// Protocol : SRP-6a, SHA-256, RFC 3526 2048-bit group ("s2k" / "s2k_fo")
// Endpoint : https://gsa.apple.com/grandslam/GsService2/lookupDirect
// spd crypto: AES-256-CBC, key/IV from HMAC-SHA256 of the SRP session key
//
// Anisette is produced by anisette.exe (AltServer-derived Windows tool),
// or fetched from a public anisette server on macOS/Linux.
// Use AnisetteData::fetch_from_exe() to run it, or
//     AnisetteData::from_server_output() to parse its stdout yourself.
//
// Declarations only — see gsa.cpp for implementations.

#include "ipatool.h"
#include "http_client.h"
#include "plist.h"
#include "anisette.h"
#include "srp.h"
#include "aes.h"
#include "sha2.h"
#include "bignum.h"
#include <nlohmann/json.hpp>

#include <string>
#include <vector>
#include <map>

// ─────────────────────────────────────────────────────────────────────────────
// dict_data — extract raw bytes from a <data> PlistValue
// (plist.h has dict_str/int/dict/arr but not dict_data)
// ─────────────────────────────────────────────────────────────────────────────
inline std::vector<uint8_t> dict_data(const PlistDict& d, const std::string& key)
{
    auto it = d.find(key);
    if (it == d.end()) return {};
    if (it->second.isData())   return it->second.dataVal;
    if (it->second.isString()) return base64_decode(it->second.str());
    return {};
}

// ─────────────────────────────────────────────────────────────────────────────
// AnisetteData — moved to anisette.h/anisette.cpp
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// GsaClient
// ─────────────────────────────────────────────────────────────────────────────
// ── Small helpers used by GsaClient ─────────────────────────────────────────

std::string gsa_gen_uuid();
std::string gsa_country(const std::string& locale);

class GsaClient {
public:
    static constexpr const char* GSA_ENDPOINT =
        "https://gsa.apple.com/grandslam/GsService2";
    // GSA User-Agent — must match the platform reported by the anisette server.
    //   Windows: iTunes Windows UA (matches Windows device info from local anisette)
    //   macOS/Linux: akd/CFNetwork Darwin UA (matches MacBook info returned by
    //                public anisette servers: X-MMe-Client-Info <MacBookPro13,2>...)
#if defined(_WIN32) || defined(_WIN64)
    static constexpr const char* ITUNES_UA =
        "iTunes/12.11.3 (Windows; Microsoft Windows 10 x64 Professional Edition "
        "(Build 19041); x64) AppleWebKit/7611.3.10.1.16";
#else
    static constexpr const char* ITUNES_UA =
        "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";
#endif
    // First-party OAuth widget key (same as used by AltStore/AltServer)
    static constexpr const char* WIDGET_KEY =
        "e0b80c3bf01cb8ef2f36302d59707be360d740c3";

    explicit GsaClient(HttpClient& http, bool debug = false)
        : m_http(http), m_debug(debug) {}

    // ── Main entry point ──────────────────────────────────────────────────────
    //
    // Runs the full two-step SRP-6a GSA handshake and returns a populated Account.
    // Throws AuthCodeRequired if 2FA is needed and authCode is empty.
    // Call again with the 6-digit code to complete.
    //
    Account login(const std::string&  email,
                  const std::string&  password,
                  const AnisetteData& anisette,
                  const std::string&  authCode = "");

private:
    HttpClient& m_http;
    bool        m_debug;

    // 2FA: GET /grandslam/GsService2/validate
    // code in "security-code" header, identity = base64(dsid:GsIdmsToken)
    // Build headers for 2FA requests (push trigger + validate)
    std::map<std::string, std::string> build_2fa_headers(
        const AnisetteData& anisette,
        const std::string& dsid,
        const std::string& idms_token);

    // ALL anisette fields must be HTTP headers (no body, unlike GSA init/complete)
    bool do_2fa_validate(const std::string& dsid, const std::string& idms_token,
                         const std::string& code,
                         const AnisetteData& anisette);

    // cpd — anisette data duplicated inside the plist body.
    // Apple returns HTTP 200 / Content-Length: 0 (silent reject)
    // when cpd is absent, even if all headers are correct.
    static PlistDict make_cpd(const AnisetteData& a);

    std::map<std::string, std::string> build_headers(const AnisetteData& a) const;

    static void check_status(const PlistDict& d, const char* step);

    std::string fetch_storefront(const Account& acc);

    static std::string iso8601_now();

    // Print outgoing request headers + first 400 chars of body
    static void dbg_request(const char* step,
                             const std::map<std::string, std::string>& hdrs,
                             const std::string& body);

    // Print incoming response: status, first 16 bytes as hex, then body text
    static void dbg_response(const char* step, const HttpResponse& r);
};
