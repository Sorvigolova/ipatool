#pragma once
//
// AppStore — C++ port of ipatool/pkg/appstore
// Cross-platform: Windows (MSVC / VS2022), Linux, macOS
//
// Declarations only — see appstore.cpp for implementations.

#include "ipatool.h"
#include "http_client.h"
#include "plist.h"
#include "gsa.h"

#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ── Storefront → country code ───────────────────────────────────────────────
// account.storeFront looks like "143441-1,32" — the numeric ID before the
// dash maps to a 2-letter ISO country code (e.g. "143441" → "US"), needed
// for iTunes Search API calls (search, lookup, lookup_by_id).
// Throws std::runtime_error if sf doesn't match any known storefront ID.
std::string country_code_from_storefront(const std::string& sf);

// ── Data types ───────────────────────────────────────────────────────────────

struct App {
    int64_t     id        = 0;
    std::string bundleID;
    std::string name;
    std::string version;
    double      price     = 0.0;
};

struct Sinf {
    int64_t              id   = 0;
    std::vector<uint8_t> data;
};

// ── JSON parsing (iTunes Search/Lookup API responses) ─────────────────────────

App app_from_json(const json& j);

struct SearchResult {
    int              count = 0;
    std::vector<App> results;
};

SearchResult parse_search_json(const std::string& body);

// ── URL / query helpers ──────────────────────────────────────────────────────

std::string url_encode(const std::string& s);
std::string build_query(const std::map<std::string, std::string>& params);

// ── AppStore class ────────────────────────────────────────────────────────────

class AppStore {
public:
    // cookieFile: path to store session cookies (persisted between login and download)
    explicit AppStore(const std::string& cookieFile = "")
        : m_http(cookieFile) {}

    // ── Login ────────────────────────────────────────────────────────────────

    // ── Login (GSA path — replaces broken iTunes fast-auth endpoint) ────────
    //
    // anisette : from AnisetteData::fetch_from_exe("anisette.exe")
    // authCode : empty on first call; fill if AuthCodeRequired is thrown
    //
    Account login(const std::string&  email,
                  const std::string&  password,
                  const AnisetteData& anisette,
                  const std::string&  authCode = "");

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

    void purchase(const Account& acc, const App& app);

    // ── Download ──────────────────────────────────────────────────────────────

    struct DownloadOutput {
        std::string       destinationPath;
        std::vector<Sinf> sinfs;
    };

    DownloadOutput download(const Account& acc,
                            const App& app,
                            const std::string& outputPath = "",
                            const std::string& externalVersionID = "",
                            ProgressCb progress = nullptr);

public:
    void set_debug(bool v) { m_debug = v; }
    void set_anisette(const AnisetteData& a) { m_anisette = a; }

    // ── List Versions ────────────────────────────────────────────────────────
    PlistDict fetch_download_info(const Account& acc, const std::string& guid,
                                  int64_t adamId, const std::string& versionId = "");

    struct ListVersionsOutput {
        std::vector<std::string> externalVersionIdentifiers;
        std::string              latestExternalVersionID;
    };

    ListVersionsOutput list_versions(const Account& acc, const App& app);

    // ── Get Version Metadata ─────────────────────────────────────────────────
    struct GetVersionMetadataOutput {
        std::string displayVersion;
        std::string releaseDate;
    };

    GetVersionMetadataOutput get_version_metadata(const Account& acc,
                                                   const App& app,
                                                   const std::string& versionID);

private:
    HttpClient   m_http;
    bool         m_debug    = false;
    AnisetteData m_anisette; // cached from login, used for store requests

    static std::string get_guid();
    static std::string get_guid_from_mac();

    // ── iTunes Store authentication (GSA path) ───────────────────────────────
    //
    // Exchanges com.apple.gs.itunes.auth token for iTunes Store session cookies.
    // Curl automatically stores Set-Cookie (amia-{dsid}, mz_at0-{dsid}, etc.)
    // into COOKIE_FILE so subsequent buyProduct / download requests send them.
    //
    // Mirrors gsa.js storeAuthenticate():
    //   POST https://buy.itunes.apple.com/.../authenticate
    //   Body:  appleId, attempt:"1", createSession:"true", guid,
    //          password:PET, rmp:"0", why:"signIn"
    //   Header: X-Apple-Identity-Token = base64(adsid:GsIdmsToken)
    //   Response sets mz_at0-{dsid} / itspod / hsaccnt cookies into COOKIE_FILE,
    //   and returns passwordToken used as X-Token in buy/download requests.
    void do_itunes_auth(Account& acc,
                        const AnisetteData& anisette,
                        const std::string& guid);

    // ── Purchase implementation ───────────────────────────────────────────────
    void do_purchase(const Account& acc, const App& app,
                     const std::string& guid, const std::string& pricingParam,
                     std::map<std::string,std::string> headers = {});

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
};
