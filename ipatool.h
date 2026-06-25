#pragma once
// Shared types used across the whole project: Account, App, Sinf, the
// ProgressCb callback signature, the IpaError exception hierarchy, and the
// Apple Store endpoint/error constants.
//
// This is pure data — no logic lives here (compare with protect.h, which
// holds the in-memory encryption logic that Account's SecureString fields
// rely on). Like PlistValue in plist.h, these types are simple enough that
// there's no .cpp to go with this .h.

#include <string>
#include <vector>
#include <functional>
#include <stdexcept>
#include <cstdint>
#include "protect.h"   // SecureString — used by Account's secret fields

// ── Constants ────────────────────────────────────────────────────────────────

inline constexpr const char* ITUNES_API_DOMAIN      = "itunes.apple.com";
inline constexpr const char* ITUNES_API_PATH_SEARCH = "/search";
inline constexpr const char* ITUNES_API_PATH_LOOKUP = "/lookup";

inline constexpr const char* PRIVATE_AS_DOMAIN         = "buy.itunes.apple.com";
inline constexpr const char* PRIVATE_AS_PATH_PURCHASE   = "/WebObjects/MZFinance.woa/wa/buyProduct";
inline constexpr const char* PRIVATE_AS_PATH_DOWNLOAD   = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct";
inline constexpr const char* PRICING_APPSTORE           = "STDQ";
inline constexpr const char* PRICING_ARCADE             = "GAME";

inline constexpr const char* FAILURE_PASSWORD_TOKEN_EXPIRED   = "2034";
inline constexpr const char* FAILURE_LICENSE_NOT_FOUND        = "9610";
inline constexpr const char* FAILURE_TEMPORARILY_UNAVAILABLE  = "2059";
inline constexpr const char* FAILURE_ALREADY_PURCHASED        = "5002";

inline constexpr const char* CUSTOMER_MSG_SUBSCRIPTION_REQ    = "Subscription Required";
inline constexpr const char* CUSTOMER_MSG_SIGN_IN             = "Sign In to the iTunes Store";

// ── Data types ───────────────────────────────────────────────────────────────

struct Account {
    // Identity
    std::string   email;
    std::string   name;
    std::string   firstName;
    std::string   lastName;
    std::string   directoryServicesID;  // DsPrsId (numeric)
    std::string   adsid;                // raw adsid (for X-Apple-Identity-Token)

    // Secrets (AES-GCM encrypted in RAM — see protect.h)
    SecureString  password;             // Apple ID password (for re-auth)
    SecureString  gsIdmsToken;          // GsIdmsToken from GSA SRP (for iTunes authenticate)
    SecureString  passwordToken;        // iTunes Store session token (X-Token for downloads)

    // GSA session tokens
    std::string   petToken;             // com.apple.gs.idms.pet  (5 min TTL)
    std::string   hbToken;             // com.apple.gs.idms.hb   (1 year TTL)

    // Store routing
    std::string   storeFront;
    std::string   pod;
};

// Progress callback: called with (bytes_so_far, total_bytes)
using ProgressCb = std::function<void(int64_t, int64_t)>;

// ── Error types ──────────────────────────────────────────────────────────────

struct IpaError : std::runtime_error {
    explicit IpaError(const std::string& msg) : std::runtime_error(msg) {}
};
struct AuthCodeRequired    : IpaError { AuthCodeRequired()    : IpaError("auth code is required") {} };
struct LicenseRequired     : IpaError { LicenseRequired()     : IpaError("license is required") {} };
struct AlreadyPurchased    : IpaError { AlreadyPurchased()    : IpaError("license already exists") {} };
struct PasswordTokenExpired: IpaError { PasswordTokenExpired(): IpaError("password token is expired") {} };
struct SubscriptionRequired: IpaError { SubscriptionRequired(): IpaError("subscription required") {} };
struct PaidAppNotSupported : IpaError { PaidAppNotSupported() : IpaError("purchasing paid apps is not supported") {} };
