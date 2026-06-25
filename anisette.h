#pragma once
// anisette.h — Anisette data (Apple device-attestation headers for GSA)
//
// What "anisette" actually is: a set of headers (X-Apple-I-MD, X-Apple-I-MD-M,
// etc.) that Apple's GSA auth endpoints require to prove the request comes
// from a real, registered Apple device. The OTP (X-Apple-I-MD) is generated
// by Apple's proprietary AOSKit/CoreADI libraries from a device "machine ID"
// — we don't currently reproduce that algorithm ourselves.
//
// Today this struct is just a thin wrapper around two existing sources:
//   - fetch_from_exe()            — runs a local anisette binary (Windows;
//                                    AltServer-derived tool) and parses its
//                                    stdout.
//   - fetch_from_public_servers() — macOS/Linux fallback: queries public
//                                    SideStore-style anisette servers over
//                                    HTTP and parses their JSON response.
//
// If/when we (or anyone else) reverse-engineer the actual OTP generation
// algorithm, the real implementation belongs in anisette.cpp, behind a new
// AnisetteData::generate_locally() — everything in gsa.h/gsa.cpp that
// consumes an AnisetteData would need no changes at all.

#include <string>
#include "http_client.h"

struct AnisetteData {
    // Required — core OTP pair
    std::string otp;            // X-Apple-I-MD        (base64 OTP)
    std::string machineID;      // X-Apple-I-MD-M      (base64 Machine ID)

    // Device identity (present in all anisette output)
    std::string localUserUUID;  // X-Apple-I-MD-LU     (base64-encoded UUID)
    std::string deviceID;       // X-Mme-Device-Id     (plain UUID string)
    std::string clientInfo;     // X-MMe-Client-Info   (<MacBookPro15,1> ...)
    std::string serialNo;       // X-Apple-I-SRL-NO    (e.g. "C02LKHBBFD57")
    std::string routingInfo;    // X-Apple-I-MD-RINFO  (e.g. "17106176")

    // Locale / time — populated from server output
    std::string locale     = "en_US";
    std::string timezone   = "PST";
    std::string clientTime;     // X-Apple-I-Client-Time (auto-filled if empty)

    bool is_complete() const { return !otp.empty() && !machineID.empty(); }

    // ── Parse key: value stdout from a local anisette binary ───────────────
    //
    // Example input (one header per line):
    //   X-Apple-I-MD: AAAABQAAABAQYo4c+dxltRQuDTdQi9qfAAAAAg==
    //   X-Apple-I-MD-M: sCkV90Yn6NWKfQxI...
    //   ...
    static AnisetteData from_server_output(const std::string& output);

    // ── Run a local anisette binary and return parsed data ──────────────────
    //
    // exe_path: full path, or just "anisette.exe"/"anisette" if it sits next
    //           to ipatool or is on PATH.
    static AnisetteData fetch_from_exe(const std::string& exe_path = "anisette.exe");

    // ── Parse JSON response from a public anisette server ───────────────────
    // Public servers (SideStore-style) return a flat JSON object with the
    // same X-Apple-I-MD* keys, e.g.:
    //   {"X-Apple-I-MD": "...", "X-Apple-I-MD-M": "...", ...}
    static AnisetteData from_json(const std::string& json_text);

    // ── Fallback: fetch from a public anisette server (macOS/Linux) ─────────
    // We can't reproduce Apple's anisette generation ourselves yet, so on
    // platforms without a local anisette binary we fall back to public
    // SideStore-style servers. Tries each server in turn, two passes total
    // (public servers are often flaky with transient 5xx).
    static AnisetteData fetch_from_public_servers(HttpClient& http, bool debug = false);

    // ── Placeholder for the real thing ───────────────────────────────────────
    // Not implemented. If the OTP algorithm ever gets reverse-engineered,
    // it goes here — same return type, so every caller (GsaClient::login,
    // do_purchase, etc.) keeps working unmodified.
    // static AnisetteData generate_locally();

private:
    static std::string trim(const std::string& s);
};
