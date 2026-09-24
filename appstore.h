#pragma once
//
// AppStore — C++ port of ipatool/pkg/appstore
// Cross-platform: Windows (MSVC / VS2022), Linux, macOS
//
// Declarations only — see appstore.cpp for implementations.
// Includes the storefront ID -> country code table and iTunes Search/Lookup
// JSON parsing, merged in here since they're App Store specific data, not
// general-purpose.

#include "ipatool.h"
#include "http_client.h"
#include "plist.h"

#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ── Data types ───────────────────────────────────────────────────────────────

// App and Sinf live in ipatool.h (shared with the rest of the project).

// ── JSON parsing (iTunes Search/Lookup API responses) ─────────────────────────

App app_from_json(const json& j);

struct SearchResult {
    int              count = 0;
    std::vector<App> results;
};

SearchResult parse_search_json(const std::string& body);

// ── Storefront -> country code ──────────────────────────────────────────────
// account.storeFront looks like "143441-1,32" — the numeric ID before the
// dash maps to a 2-letter ISO country code (e.g. "143441" -> "US"), needed
// for iTunes Search API calls (search, lookup, lookup_by_id).
// Throws std::runtime_error if sf doesn't match any known storefront ID.
std::string country_code_from_storefront(const std::string& sf);

// ── URL / query helpers ──────────────────────────────────────────────────────

std::string url_encode(const std::string& s);
std::string build_query(const std::map<std::string, std::string>& params);

// ── AppStore class ────────────────────────────────────────────────────────────

// Forward declaration — SapSigner.h for full type
class SapSigner;

class AppStore {
public:
    // cookieFile: path to store session cookies (persisted between login and download)
    explicit AppStore(const std::string& cookieFile = "")
        : m_http(cookieFile) {}

    // ── Bag ──────────────────────────────────────────────────────────────────

    struct BagOutput {
        std::string authEndpoint;
        std::string redownloadEndpoint;  // https://downloaddispatch.itunes.apple.com/r/redownload
        std::string updateEndpoint;      // https://downloaddispatch.itunes.apple.com/up/updateProduct
        // SAP config fields (v2.4.0+ — from bag.xml sign-sap-* keys)
        std::string          signSapSetup;        // sign-sap-setup URL
        std::string          signSapSetupCert;    // sign-sap-setup-cert URL
        uint32_t             sapVersion   = 0;   // sign-sap-version (must be 200)
        std::vector<uint8_t> hardwareID;          // raw MAC bytes for SapSigner::Config
    };

    // Fetch bag.xml and return both auth and redownload endpoints.
    // Call this before download / list-versions / get-version-metadata to
    // obtain the redownloadEndpoint needed for the 5002 fallback.
    BagOutput fetch_bag();

    // ── Login ────────────────────────────────────────────────────────────────

    Account login(const std::string& email,
                  const std::string& password,
                  const std::string& authCode = "",
                  const std::string& endpoint = "");

    // ── Search ───────────────────────────────────────────────────────────────

    struct SearchOutput {
        int              count = 0;
        std::vector<App> results;
    };

    SearchOutput search(const Account& acc, const std::string& term, int limit = 5);

    // ── Lookup by bundle ID ───────────────────────────────────────────────────

    App lookup(const Account& acc, const std::string& bundleID);

    // ── Lookup by numeric app ID ──────────────────────────────────────────────

    App lookup_by_id(const Account& acc, int64_t appID);

    // ── Purchase (free apps) ──────────────────────────────────────────────────

    PlistDict purchase(const Account& acc, const App& app); // returns purchase result incl. songList for paid apps

    // ── Download ──────────────────────────────────────────────────────────────

    struct DownloadOutput {
        std::string       destinationPath;
        std::vector<Sinf> sinfs;
    };

    DownloadOutput download(const Account& acc,
                            const App& app,
                            const std::string& outputPath = "",
                            const std::string& externalVersionID = "",
                            ProgressCb progress = nullptr,
                            const std::string& redownloadEndpoint = "");

public:
    void set_debug(bool v); // also enables SapSigner HTTP dumps

    // ── List Versions ────────────────────────────────────────────────────────
    struct ListVersionsOutput {
        std::vector<std::string> externalVersionIdentifiers;
        std::string              latestExternalVersionID;
    };

    ListVersionsOutput list_versions(const Account& acc, const App& app,
                                     const std::string& redownloadEndpoint = "");

    // ── Get Version Metadata ─────────────────────────────────────────────────
    struct GetVersionMetadataOutput {
        std::string displayVersion;
        std::string releaseDate;
    };

    GetVersionMetadataOutput get_version_metadata(const Account& acc,
                                                   const App& app,
                                                   const std::string& versionID,
                                                   const std::string& redownloadEndpoint = "");

private:
    HttpClient m_http;
    bool       m_debug = false;
    // Bag "updateProduct" endpoint, remembered by fetch_bag_impl() so the
    // redownload fallback can use it without changing public signatures.
    std::string m_updateEndpoint;

    static std::string get_guid();

    // ── sendDownloadProduct — shared volumeStore->redownload helper ─────────
    //
    // Sends to volumeStore first (uses externalVersionId version key).
    // On failureType "5002" (licensed app), falls back to bag-resolved
    // redownloadProduct (uses appExtVrsId key):
    //   - redownload serves the app                    -> use redownload response
    //   - redownload: empty songList + "No Longer Available"
    //                                                  -> transient 5002 -> retry volumeStore
    // Returns the top-level response PlistDict for the caller to inspect.
    //
    // isMac: skip the iOS catalog version lookup on the redownload fallback
    // (the lookup would pin an iOS build for a macOS download).
    PlistDict send_download_product(const Account& acc, const App& app,
                                     const std::string& guid,
                                     const std::string& externalVersionID,
                                     const std::string& redownloadEndpoint,
                                     bool isMac = false);

    // ── Platform version lookup (port of upstream appstore_platform_version_lookup.go)
    //
    // Resolves the latest iOS external version ID via the MZStorePlatform
    // lookup (p=mdm-lockup). Tries catalogs in order: enterprisestore, then the
    // consumer catalogs iphone and ipad (upstream e5211d6 — some storefronts
    // have no enterprise listing even when the consumer catalogs contain the
    // app). The account's country is kept for every lookup.
    // Throws IpaError when no catalog lists the app or on HTTP failure.
    std::string lookup_latest_external_version_id(const Account& acc, const App& app);

    // ── Redownload + updateProduct fallback (port of upstream sendDownloadProduct)
    //
    // POSTs redownloadProduct with the Go request shape (headers: Content-Type,
    // iCloud-DSID, X-Dsid; payload: creditDisplay, guid, salableAdamId,
    // serialNumber, appExtVrsId). The version is pinned to externalVersionID or,
    // for iOS, the latest from the platform catalogs.
    // If redownload answers HTTP 500 with an empty body, or 200 with a
    // "No Longer Available" message, and the version is pinned, the same request
    // goes to the bag's updateProduct endpoint. With needSinfs (download only),
    // a 200 answer whose item carries no sinf data also goes to updateProduct.
    // Returns the decoded response of the last request sent.
    PlistDict redownload_product(const Account& acc, const App& app,
                                 const std::string& guid,
                                 const std::string& redownloadEndpoint,
                                 const std::string& externalVersionID,
                                 bool isMac, const char* label,
                                 bool needSinfs = false);

    // updateProduct request (upstream sendUpdateProduct). Returns the response
    // as-is when it carries a failureType; throws IpaError on a customer
    // message, a non-200 status, or a response that does not match the
    // requested app ID / version / bundle ID.
    PlistDict send_update_product(const Account& acc, const App& app,
                                  const std::string& guid,
                                  const std::string& externalVersionID);

    // Version to pin on a redownload request: externalVersionID if set,
    // otherwise the result of lookup_latest_external_version_id(). Unpinned
    // redownloads can return the wrong platform's build (e.g. tvOS).
    // Returns "" (unpinned, previous behaviour) if the lookup fails.
    std::string redownload_version_id(const Account& acc, const App& app,
                                      const std::string& externalVersionID);

    // Download (macOS) — decrypts .pkg using StoreAgentMachine
    DownloadOutput download_mac(const Account& acc, const App& app,
                                const std::string& outputPath,
                                ProgressCb progress,
                                const std::string& redownloadEndpoint);




    // ── Bag (fetch auth + redownload endpoints) ──────────────────────────────
    BagOutput fetch_bag_impl(const std::string& guid);

    std::string fetch_bag_auth_endpoint(const std::string& guid);

    // ── Login implementation ─────────────────────────────────────────────────
    Account do_login(const std::string& email,
                     const std::string& password,
                     const std::string& authCode,
                     const std::string& guid,
                     const std::string& baseEndpoint,
                     SapSigner* signer = nullptr); // nullptr = unsigned (pre-v2.4.0)

    // ── Purchase implementation ───────────────────────────────────────────────
    PlistDict do_purchase(const Account& acc, const App& app,
                         const std::string& guid, const std::string& pricingParam);

    // ── ZIP patching ──────────────────────────────────────────────────────────
    // Injects a patched iTunesMetadata.plist into the downloaded IPA.
    // Uses minizip when available; falls back to a pure C++ copy without patching.
    //
    // Step 1 (applyPatches): rewrite iTunesMetadata.plist with apple-id/userName
    // Step 2 (replicateSinf): inject sinf file(s) into Payload/App.app/SC_Info/
    //   - If SC_Info/Manifest.plist exists: use SinfPaths from it (zip with sinfs by index)
    //   - Otherwise: write sinfs[0] to SC_Info/{CFBundleExecutable}.sinf
    //
    // Both steps read from srcPath (.tmp) and write to dstPath (final .ipa),
    // matching the two-pass approach in the original Go code.
    void apply_patches(const PlistDict& item,
                       const Account&   acc,
                       const std::string& srcPath,
                       const std::string& dstPath,
                       const std::vector<Sinf>& sinfs);

#ifdef HAVE_MINIZIP
    static void patch_with_minizip(const std::string& srcPath,
                                   const std::string& dstPath,
                                   const std::vector<uint8_t>& metaBytes,
                                   const std::vector<uint8_t>& artworkBytes,
                                   const std::vector<Sinf>& sinfs);

    // Extract a string value from a binary or XML plist by key name.
    // Used to read CFBundleExecutable from Info.plist without a full plist parser.
    static std::string extract_plist_string(const std::vector<uint8_t>& data,
                                             const std::string& key);

    // Parse SinfPaths array from SC_Info/Manifest.plist (XML or binary plist)
    static std::vector<std::string> extract_sinf_paths(const std::vector<uint8_t>& data);
#endif

    // ── URL builders ─────────────────────────────────────────────────────────
    static std::string search_url(const std::string& term,
                                   const std::string& cc, int limit);
    static std::string lookup_url(const std::string& bundleID,
                                   const std::string& cc);

    // ── Path helpers (C++17 std::filesystem — no POSIX needed) ───────────────
    static std::string resolve_destination(const App& app,
                                           const std::string& version,
                                           const std::string& outputPath);
    static std::string make_filename(const App& app, const std::string& version);
    static int64_t file_size(const std::string& path);

    // ── String helpers ────────────────────────────────────────────────────────
    static std::string strip_spaces(const std::string& s);
    static std::string str_lower(const char* s);
};
