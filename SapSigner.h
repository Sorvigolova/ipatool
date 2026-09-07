#pragma once
#include "SapMachine.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
//  ISapHttpClient
// ─────────────────────────────────────────────────────────────────────────────
struct ISapHttpClient {
    virtual ~ISapHttpClient() = default;
    virtual std::vector<uint8_t> Get(std::string_view url) = 0;
    virtual std::vector<uint8_t> Post(std::string_view url,
                                      std::span<const uint8_t> body,
                                      std::string_view contentType) = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  SapWinHttpClient  — built-in WinHTTP implementation
// ─────────────────────────────────────────────────────────────────────────────
class SapWinHttpClient final : public ISapHttpClient {
public:
    explicit SapWinHttpClient(std::wstring userAgent = L"iTunes/12.13");
    ~SapWinHttpClient() override;

    std::vector<uint8_t> Get(std::string_view url) override;
    std::vector<uint8_t> Post(std::string_view url,
                               std::span<const uint8_t> body,
                               std::string_view contentType) override;
private:
    std::vector<uint8_t> Send(std::string_view method,
                               std::string_view url,
                               std::span<const uint8_t> body,
                               std::string_view contentType);
    std::wstring userAgent_;
    void* hSession_ = nullptr; // HINTERNET
};

// ─────────────────────────────────────────────────────────────────────────────
//  SapSigner  — full port of signer_local.go
//
//  Usage:
//      SapSigner::Config cfg;
//      cfg.setupURL       = bag["sign-sap-setup"];
//      cfg.certificateURL = bag["sign-sap-setup-cert"];
//      cfg.version        = 200;
//      cfg.hardwareID     = SapSigner::LocalHardwareID();
//
//      auto signer = SapSigner::Create(cfg, coreFP, commerceCore,
//                                      commerceKit, coreFPIcxs);
//
//      // For each authenticate POST:
//      std::string sig = signer->SignBase64(plistBody);
//      // HTTP header: "X-Apple-ActionSignature: " + sig
// ─────────────────────────────────────────────────────────────────────────────
class SapSigner {
public:
    static constexpr uint32_t kSupportedVersion = 200;

    struct Config {
        std::string          setupURL;
        std::string          certificateURL;
        uint32_t             version    = 200;
        std::vector<uint8_t> hardwareID;    // 6 bytes from MAC address
    };

    // Create and perform the full SAP handshake.
    // httpClient == nullptr → uses SapWinHttpClient.
    static std::unique_ptr<SapSigner> Create(
        const Config&        config,
        std::vector<uint8_t> coreFP,
        std::vector<uint8_t> commerceCore,
        std::vector<uint8_t> commerceKit,
        std::vector<uint8_t> coreFPIcxs,
        ISapHttpClient*      httpClient = nullptr
    );

    ~SapSigner();

    // Sign raw bytes — returns raw signature.
    std::vector<uint8_t> Sign(std::span<const uint8_t> input);

    // Sign and base64-encode — ready for X-Apple-ActionSignature header.
    std::string SignBase64(std::span<const uint8_t> input);
    std::string SignBase64(std::string_view input);

    void Close();

    // ── hardware ID helpers ───────────────────────────────────────────────────
    // Parse "AA:BB:CC:DD:EE:FF" → 6 bytes
    static std::vector<uint8_t> HardwareIDFromMAC(std::string_view mac);
    // Return first non-loopback adapter MAC on this machine
    static std::vector<uint8_t> LocalHardwareID();

private:
    SapSigner() = default;

    std::unique_ptr<SapMachine> machine_;
    uint64_t                    sapCtx_  = 0;
    std::vector<uint8_t>        hardware_;
    std::mutex                  mu_;
    bool                        closed_  = false;
};

// ─────────────────────────────────────────────────────────────────────────────
//  SapPlist  — minimal Apple XML plist read/write (no external dependency)
// ─────────────────────────────────────────────────────────────────────────────
namespace SapPlist {
    // Extract binary <data> for the given <key>. Throws if missing.
    std::vector<uint8_t> ExtractData(const std::vector<uint8_t>& xml, std::string_view key);

    // Produce a one-entry XML plist with a single <data> value.
    std::vector<uint8_t> MakeData(std::string_view key, std::span<const uint8_t> value);
}

// ─────────────────────────────────────────────────────────────────────────────
//  SapBase64
// ─────────────────────────────────────────────────────────────────────────────
namespace SapBase64 {
    std::string          Encode(std::span<const uint8_t> data);
    std::vector<uint8_t> Decode(std::string_view b64);
}
