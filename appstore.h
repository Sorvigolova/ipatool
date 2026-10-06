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
        std::string redownloadEndpoint;          // bag key redownloadProduct → https://downloaddispatch.itunes.apple.com/r/redownload
        std::string updateEndpoint;              // bag key updateProduct → https://downloaddispatch.itunes.apple.com/up/updateProduct
        std::string volumeStoreDownloadEndpoint; // bag key volumeStoreDownloadProduct → https://downloaddispatch.itunes.apple.com/WebObjects/DownloadDispatch.woa/wa/ent/download
        std::string songDownloadDoneEndpoint;    // bag key songDownloadDone → https://buy.itunes.apple.com/WebObjects/MZFastFinance.woa/wa/songDownloadDone
        // SAP config fields (v2.4.0+ — from bag.xml sign-sap-* keys)
        std::string          signSapSetup;       // bag key sign-sap-setup → https://fpinit.itunes.apple.com/v1/signSapSetup/legacy
        std::string          signSapSetupCert;   // bag key sign-sap-setup-cert → https://s.mzstatic.com/sap/setupCert.plist
        uint32_t             sapVersion   = 0;   // sign-sap-version (must be 200)
        std::vector<uint8_t> hardwareID;         // raw MAC bytes for SapSigner::Config
    };

    // Fetch and parse bag.xml. Returns every endpoint the download/auth flow needs
    // — authenticateAccount, volumeStoreDownloadProduct, redownloadProduct,
    // updateProduct, songDownloadDone — plus the SAP signing config. Call before
    // download / list-versions / get-version-metadata; login() uses it too.
    BagOutput fetch_bag(const std::string& guid = "");

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
                            const std::string& redownloadEndpoint = "",
                            const std::string& volumeStoreDownloadEndpoint = "",
                            const std::string& kbsyncB64 = "",
                            const std::string& songDownloadDoneEndpoint = "");

    // True when the last download()'s volumeStoreDownload stage was rejected in a way
    // that suggests the cached kbsync is stale (HTTP >= 500). The caller uses
    // this to drop the cached blob so the next run regenerates it.
    bool kbsync_rejected() const { return m_kbsyncRejected; }

public:
    void set_debug(bool v); // also enables SapSigner HTTP dumps

    // ── kbsync ────────────────────────────────────────────────────────────────
    // Generates the kbsync blob for an account DSID by running storeagent's
    // FairPlayGlobalContextInit + FairPlayKBSyncDataWithDSID under the
    // emulator. Local only — no request is sent to Apple. Throws on failure.
    std::vector<uint8_t> generate_kbsync(uint64_t dsid);

    // ── List Versions ────────────────────────────────────────────────────────
    struct ListVersionsOutput {
        std::vector<std::string> externalVersionIdentifiers;
        std::string              latestExternalVersionID;
    };

    ListVersionsOutput list_versions(const Account& acc,
                                    const App& app,
                                    const std::string& redownloadEndpoint = "",
                                    const std::string& volumeStoreDownloadEndpoint = "",
                                    const std::string& kbsyncB64 = "");

    // ── Get Version Metadata ─────────────────────────────────────────────────
    struct GetVersionMetadataOutput {
        std::string displayVersion;
        std::string releaseDate;
    };

    GetVersionMetadataOutput get_version_metadata(const Account& acc,
                                                   const App& app,
                                                   const std::string& versionID,
                                                   const std::string& redownloadEndpoint = "",
                                                   const std::string& volumeStoreDownloadEndpoint = "",
                                                   const std::string& kbsyncB64 = "");

private:
    HttpClient m_http;
    bool       m_debug = false;
    bool       m_kbsyncRejected = false; // set by the volumeStoreDownload stage, read by caller

    // ── volumeStoreDownloadProduct (bag download endpoint, kbsync-signed) ────────
    // POSTs the bag's volumeStoreDownloadProduct with the base64 kbsync and returns
    // the decoded response; httpStatus receives the HTTP status so the caller can
    // tell a stale-kbsync rejection (>= 500) from a normal refusal. With authed, the
    // payload carries hasBeenAuthedForBuy=true (the 2042 "confirm download" retry).
    PlistDict volume_store_download_product(const Account& acc, const App& app,
                                const std::string& guid,
                                const std::string& volumeStoreDownloadEndpoint,
                                const std::string& kbsyncB64,
                                const std::string& externalVersionID,
                                bool authed,
                                int& httpStatus);
    // Bag "updateProduct" endpoint, remembered by fetch_bag() so resolve_download
    // can use it without changing public signatures.
    std::string m_updateEndpoint;

    // GET the bag's songDownloadDone URL (built with the account pod + songId +
    // guid) to report a completed download to Apple. Returns true when the
    // response carries jingleDocType "success". Best-effort; never fatal.
    bool report_download_done(const Account& acc, int64_t songId,
                              const std::string& downloadId,
                              const std::string& songDownloadDoneEndpoint);

    static std::string get_guid();

    // ── resolve_download — stateless 3-endpoint cascade ─────────────────────────
    // Tries the three bag endpoints in order — volumeStoreDownloadProduct (kbsync),
    // redownloadProduct, updateProduct — and returns the first response that serves
    // the app: a songList item, with sinf data when needSinfs (download) or just
    // metadata when not (list-versions / get-version-metadata). Carries the 2042
    // auth-dialog retry and surfaces PasswordTokenExpired; when nothing serves and
    // the account simply has no license it throws LicenseRequired so a --purchase
    // caller can acquire it.
    PlistDict resolve_download(const Account& acc, const App& app,
                               const std::string& guid,
                               const std::string& externalVersionID,
                               const std::string& redownloadEndpoint,
                               const std::string& volumeStoreDownloadEndpoint,
                               const std::string& kbsyncB64,
                               bool isMac, bool needSinfs);

    // ── Platform version lookup (port of upstream appstore_platform_version_lookup.go)
    //
    // Resolves the latest iOS external version ID via the MZStorePlatform
    // lookup (p=mdm-lockup). Tries catalogs in order: enterprisestore, then the
    // consumer catalogs iphone and ipad (upstream e5211d6 — some storefronts
    // have no enterprise listing even when the consumer catalogs contain the
    // app). The account's country is kept for every lookup.
    // Throws IpaError when no catalog lists the app or on HTTP failure.
    std::string lookup_latest_external_version_id(const Account& acc, const App& app);

    // ── redownloadProduct (bag) — pure endpoint call ────────────────────────────
    // POSTs redownloadProduct with the Go request shape (headers: Content-Type,
    // iCloud-DSID, X-Dsid; payload: creditDisplay, guid, salableAdamId, serialNumber,
    // appExtVrsId=pin) and returns the decoded response plus its HTTP status. The
    // version pin is computed by the caller; all cascade decisions (falling on to
    // updateProduct, concluding a missing license) live in resolve_download.
    PlistDict redownload_product(const Account& acc, const App& app,
                                 const std::string& guid,
                                 const std::string& redownloadEndpoint,
                                 const std::string& pin,
                                 const char* label,
                                 int& httpStatus);

    // updateProduct request (upstream sendUpdateProduct). Returns the response
    // as-is when it carries a failureType; throws IpaError on a customer
    // message, a non-200 status, or a response that does not match the
    // requested app ID / version / bundle ID.
    PlistDict update_product(const Account& acc, const App& app,
                             const std::string& guid,
                             const std::string& externalVersionID);

    // Version to pin on a redownload/update request: externalVersionID if set,
    // otherwise the result of lookup_latest_external_version_id(). Unpinned
    // redownloads can return the wrong platform's build (e.g. tvOS).
    // Returns "" (unpinned, previous behaviour) if the lookup fails.
    std::string redownload_version_id(const Account& acc, const App& app,
                                      const std::string& externalVersionID);




    // ── Bag (fetch bag.xml: all download/auth endpoints + SAP config) ────────

    // ── Login implementation ─────────────────────────────────────────────────
    Account do_login(const std::string& email,
                     const std::string& password,
                     const std::string& authCode,
                     const std::string& guid,
                     const std::string& baseEndpoint,
                     SapSigner& signer);   // every authenticate POST is SAP-signed

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
                                           const std::string& outputPath,
                                           const std::string& displayName = "",
                                           const std::string& ext = ".ipa");
    static std::string make_filename(const App& app, const std::string& version,
                                     const std::string& displayName = "",
                                     const std::string& ext = ".ipa");
    static int64_t file_size(const std::string& path);

    // ── String helpers ────────────────────────────────────────────────────────
    static std::string strip_spaces(const std::string& s);
    static std::string str_lower(const char* s);
};
