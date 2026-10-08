#include "appstore.h"
#include "SapSigner.h"   // SAP signing (v2.4.0+)
#include "device_mac.h"  // device MAC / GUID
#include "StoreAgentMachine.h"
#include <thread>
#include <chrono>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <filesystem>   // C++17 — replaces getcwd / stat / S_ISDIR
#include <regex>
#include <ctime>
#include <openssl/evp.h>   // MD5 (EVP) for whole-image download verification

// ── Platform headers ──────────────────────────────────────────────────────────

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <iphlpapi.h>
#  if defined(_MSC_VER)
// MSVC auto-links via these pragmas; MinGW/GCC links the same libs through CMake.
#    pragma comment(lib, "iphlpapi.lib")
#    pragma comment(lib, "ws2_32.lib")
#  endif
#else
#  include <sys/socket.h>
#  include <sys/ioctl.h>
#  include <net/if.h>
#  include <ifaddrs.h>
#  ifdef __linux__
#    include <netpacket/packet.h>
#  elif defined(__APPLE__)
#    include <net/if_dl.h>
#  endif
#endif

// ── minizip for cross-platform ZIP writing ────────────────────────────────────

#ifdef HAVE_MINIZIP
#  include <minizip/zip.h>
#  include <minizip/unzip.h>
#  ifdef _WIN32
#    include <minizip/iowin32.h>   // CreateFileW-based I/O for Unicode paths
#  endif
#endif

#include "path_utf8.h"   // ipt::fs_path / ipt::utf8_to_wide — Unicode paths on Windows

namespace fs = std::filesystem;

#ifdef HAVE_MINIZIP
// minizip's default ioapi opens files with the narrow CRT fopen, which mangles
// non-ASCII (e.g. Cyrillic) paths on Windows. On Windows route zip/unzip through
// the win32 wide-char I/O (CreateFileW) with a UTF-16 path; elsewhere the plain
// UTF-8 path works natively.
static unzFile ipt_unzOpen(const std::string& path) {
#  ifdef _WIN32
    zlib_filefunc64_def ff;
    fill_win32_filefunc64W(&ff);
    std::wstring w = ipt::utf8_to_wide(path);
    return unzOpen2_64(reinterpret_cast<const void*>(w.c_str()), &ff);
#  else
    return unzOpen(path.c_str());
#  endif
}
static zipFile ipt_zipOpen(const std::string& path, int append) {
#  ifdef _WIN32
    zlib_filefunc64_def ff;
    fill_win32_filefunc64W(&ff);
    std::wstring w = ipt::utf8_to_wide(path);
    return zipOpen2_64(reinterpret_cast<const void*>(w.c_str()), append, nullptr, &ff);
#  else
    return zipOpen(path.c_str(), append);
#  endif
}
#endif

#include "sap_resources.h"
#include "sap_embedded_assets.h"

// Lowercase hex MD5 of a whole file (streamed), used to verify a finished
// download against the <key>md5</key> the store returns. "" on open/hash error.
static std::string md5_file_hex(const std::string& path) {
    FILE* f = ipt::fopen_utf8(path, "rb");
    if (!f) return "";
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return ""; }
    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx); fclose(f); return "";
    }
    std::vector<uint8_t> buf(1u << 20);  // 1 MiB chunks
    size_t n;
    while ((n = fread(buf.data(), 1, buf.size(), f)) > 0)
        EVP_DigestUpdate(ctx, buf.data(), n);
    fclose(f);
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = 0;
    EVP_DigestFinal_ex(ctx, md, &mdLen);
    EVP_MD_CTX_free(ctx);
    static const char* hexd = "0123456789abcdef";
    std::string out;
    out.reserve(mdLen * 2);
    for (unsigned i = 0; i < mdLen; ++i) {
        out.push_back(hexd[md[i] >> 4]);
        out.push_back(hexd[md[i] & 0xF]);
    }
    return out;
}

// Case-insensitive ASCII equality (md5 hex compare).
static bool ascii_iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) return false;
    return true;
}

// Load a SAP dylib asset.
// Priority: 1) Linux/macOS objcopy embedded  2) Windows RCDATA  3) file fallback
static std::vector<uint8_t> load_sap_asset(const char* name) {
#ifdef SAP_ASSETS_EMBEDDED
    // Linux/macOS: symbols injected by objcopy --input binary
    struct { const char* name; const uint8_t* start; const uint8_t* end; } kEmbed[] = {
        { "CoreFP",       _binary_CoreFP_start,       _binary_CoreFP_end       },
        { "CommerceCore", _binary_CommerceCore_start, _binary_CommerceCore_end },
        { "CommerceKit",  _binary_CommerceKit_start,  _binary_CommerceKit_end  },
        { "CoreFP.icxs",  _binary_CoreFP_icxs_start,  _binary_CoreFP_icxs_end  },
        { "storeagent",   _binary_storeagent_start,   _binary_storeagent_end   },
    };
    for (auto& e : kEmbed) {
        if (std::strcmp(e.name, name) == 0 && e.start && e.end > e.start)
            return std::vector<uint8_t>(e.start, e.end);
    }
#elif defined(_WIN32)
    // Windows: RCDATA resources compiled in via sap_resources.rc
    static const struct { const char* name; int id; } kMap[] = {
        { "CoreFP",       IDR_SAP_COREFP       },
        { "CommerceCore", IDR_SAP_COMMERCECORE  },
        { "CommerceKit",  IDR_SAP_COMMERCEKIT   },
        { "CoreFP.icxs",  IDR_SAP_COREFP_ICXS  },
        { "storeagent",   IDR_SAP_STOREAGENT    },
    };
    for (auto& e : kMap) {
        if (std::strcmp(e.name, name) == 0) {
            HRSRC hRes = FindResourceA(nullptr, MAKEINTRESOURCEA(e.id), RT_RCDATA);
            if (hRes) {
                HGLOBAL hMem = LoadResource(nullptr, hRes);
                if (hMem) {
                    DWORD   sz   = SizeofResource(nullptr, hRes);
                    void*   data = LockResource(hMem);
                    if (data && sz > 0)
                        return std::vector<uint8_t>(
                            static_cast<const uint8_t*>(data),
                            static_cast<const uint8_t*>(data) + sz);
                }
            }
            break;
        }
    }
#endif

    // Fallback: load from file (development / unsupported platform)
    std::string path = std::string("sap_assets/") + name;
    std::ifstream f(path, std::ios::binary);
    if (!f) throw IpaError(std::string("SAP asset not found: ") + path +
                           " (not embedded in binary and file missing)");
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                std::istreambuf_iterator<char>());
}


// ─────────────────────────────────────────────────────────────────────────────
// Storefront -> country code
// ─────────────────────────────────────────────────────────────────────────────

struct StorefrontEntry { const char* cc; const char* id; };

static const StorefrontEntry STOREFRONT_TABLE[] = {
    {"AE","143481"},{"AG","143540"},{"AI","143538"},{"AL","143575"},{"AM","143524"},
    {"AO","143564"},{"AR","143505"},{"AT","143445"},{"AU","143460"},{"AZ","143568"},
    {"BB","143541"},{"BD","143490"},{"BE","143446"},{"BG","143526"},{"BH","143559"},
    {"BM","143542"},{"BN","143560"},{"BO","143556"},{"BR","143503"},{"BS","143539"},
    {"BW","143525"},{"BY","143565"},{"BZ","143555"},{"CA","143455"},{"CH","143459"},
    {"CI","143527"},{"CL","143483"},{"CN","143465"},{"CO","143501"},{"CR","143495"},
    {"CY","143557"},{"CZ","143489"},{"DE","143443"},{"DK","143458"},{"DM","143545"},
    {"DO","143508"},{"DZ","143563"},{"EC","143509"},{"EE","143518"},{"EG","143516"},
    {"ES","143454"},{"FI","143447"},{"FR","143442"},{"GB","143444"},{"GD","143546"},
    {"GE","143615"},{"GH","143573"},{"GR","143448"},{"GT","143504"},{"GY","143553"},
    {"HK","143463"},{"HN","143510"},{"HR","143494"},{"HU","143482"},{"ID","143476"},
    {"IE","143449"},{"IL","143491"},{"IN","143467"},{"IQ","143617"},{"IS","143558"},
    {"IT","143450"},{"JM","143511"},{"JO","143528"},{"JP","143462"},{"KE","143529"},
    {"KN","143548"},{"KR","143466"},{"KW","143493"},{"KY","143544"},{"KZ","143517"},
    {"LB","143497"},{"LC","143549"},{"LI","143522"},{"LK","143486"},{"LT","143520"},
    {"LU","143451"},{"LV","143519"},{"MD","143523"},{"MG","143531"},{"MK","143530"},
    {"ML","143532"},{"MN","143592"},{"MO","143515"},{"MS","143547"},{"MT","143521"},
    {"MU","143533"},{"MV","143488"},{"MX","143468"},{"MY","143473"},{"NE","143534"},
    {"NG","143561"},{"NI","143512"},{"NL","143452"},{"NO","143457"},{"NP","143484"},
    {"NZ","143461"},{"OM","143562"},{"PA","143485"},{"PE","143507"},{"PH","143474"},
    {"PK","143477"},{"PL","143478"},{"PT","143453"},{"PY","143513"},{"QA","143498"},
    {"RO","143487"},{"RS","143500"},{"RU","143469"},{"SA","143479"},{"SE","143456"},
    {"SG","143464"},{"SI","143499"},{"SK","143496"},{"SN","143535"},{"SR","143554"},
    {"SV","143506"},{"TC","143552"},{"TH","143475"},{"TN","143536"},{"TR","143480"},
    {"TT","143551"},{"TW","143470"},{"TZ","143572"},{"UA","143492"},{"UG","143537"},
    {"US","143441"},{"UY","143514"},{"UZ","143566"},{"VC","143550"},{"VE","143502"},
    {"VG","143543"},{"VN","143471"},{"YE","143571"},{"ZA","143472"},
};

std::string country_code_from_storefront(const std::string& sf) {
    // storefront looks like "143441-1,32" — first part before '-' is the numeric ID
    std::string numeric = sf;
    auto dash = sf.find('-');
    if (dash != std::string::npos) numeric = sf.substr(0, dash);
    auto comma = numeric.find(',');
    if (comma != std::string::npos) numeric = numeric.substr(0, comma);

    for (auto& entry : STOREFRONT_TABLE) {
        if (numeric == entry.id) return entry.cc;
    }
    throw std::runtime_error("country code mapping for store front (" + sf + ") was not found");
}

// ── JSON parsing (iTunes Search/Lookup API responses) ─────────────────────────

App app_from_json(const json& j) {
    App a;
    if (j.contains("trackId")   && j["trackId"].is_number())   a.id       = j["trackId"].get<int64_t>();
    if (j.contains("bundleId")  && j["bundleId"].is_string())  a.bundleID = j["bundleId"].get<std::string>();
    if (j.contains("trackName") && j["trackName"].is_string()) a.name     = j["trackName"].get<std::string>();
    if (j.contains("version")   && j["version"].is_string())   a.version  = j["version"].get<std::string>();
    if (j.contains("price")     && j["price"].is_number())     a.price    = j["price"].get<double>();
    return a;
}

SearchResult parse_search_json(const std::string& body) {
    SearchResult out;
    try {
        auto j = json::parse(body);
        if (j.contains("resultCount") && j["resultCount"].is_number())
            out.count = j["resultCount"].get<int>();
        if (j.contains("results") && j["results"].is_array())
            for (auto& item : j["results"])
                out.results.push_back(app_from_json(item));
    } catch (...) {}
    return out;
}

// ── URL encode helper ─────────────────────────────────────────────────────────

std::string url_encode(const std::string& s) {
    // ASCII-only unreserved set, checked explicitly: std::isalnum is
    // locale-dependent and on Windows (e.g. a CP1251 locale) can classify high
    // UTF-8 bytes as "alphanumeric", leaving them unescaped and corrupting a
    // Cyrillic term in the query. Also zero-pad each byte (%02X), so a byte
    // below 0x10 is not emitted as a single hex digit.
    static const char* hexd = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back((char)c);
        } else {
            out.push_back('%');
            out.push_back(hexd[c >> 4]);
            out.push_back(hexd[c & 0x0F]);
        }
    }
    return out;
}

std::string build_query(const std::map<std::string, std::string>& params) {
    std::string q;
    for (auto& [k, v] : params) {
        if (!q.empty()) q += '&';
        q += url_encode(k) + '=' + url_encode(v);
    }
    return q;
}

// ── Debug request/response dumps (--debug) ────────────────────────────────────

// Session tokens are shortened so a --debug log can be shared safely.
static std::string debug_mask_header(const std::string& name, const std::string& value) {
    if (name == "X-Token" && value.size() > 8)
        return value.substr(0, 4) + "..." + value.substr(value.size() - 4)
             + " (" + std::to_string(value.size()) + " chars)";
    return value;
}

static void debug_dump_request(const char* label, const char* method,
                               const std::string& url,
                               const std::map<std::string, std::string>& headers,
                               const std::string& body) {
    fprintf(stderr, "[DEBUG] ── %s request ──\n", label);
    fprintf(stderr, "[DEBUG] %s %s\n", method, url.c_str());
    fprintf(stderr, "[DEBUG] request headers:\n");
    for (auto& [k, v] : headers)
        fprintf(stderr, "  %s: %s\n", k.c_str(), debug_mask_header(k, v).c_str());
    fprintf(stderr, "[DEBUG] request body (%zu bytes):\n%s\n", body.size(), body.c_str());
}

static void debug_dump_response(const char* label, const HttpResponse& res) {
    fprintf(stderr, "[DEBUG] ── %s response ──\n", label);
    fprintf(stderr, "[DEBUG] status: %d\n", res.statusCode);
    fprintf(stderr, "[DEBUG] response headers:\n");
    for (auto& [k, v] : res.headers)
        fprintf(stderr, "  %s: %s\n", k.c_str(), v.c_str());
    fprintf(stderr, "[DEBUG] response body (%zu bytes):\n%s\n",
            res.body.size(), res.body.empty() ? "<empty>" : res.body.c_str());
}

// A songList item is usable as a download source only if it carries sinf data
// ("sinf" for iOS, "dpInfo" for macOS). Apple sometimes returns the item
// without it — such a response is treated like an empty songList.
static bool has_sinfs(const PlistArray& songList) {
    if (songList.empty() || !songList[0].isDict()) return false;
    auto it = songList[0].dictVal.find("sinfs");
    if (it == songList[0].dictVal.end() || !it->second.isArray()) return false;
    for (const auto& s : it->second.arrayVal) {
        if (!s.isDict()) continue;
        for (const char* key : {"sinf", "dpInfo"}) {
            auto f = s.dictVal.find(key);
            if (f != s.dictVal.end() && f->second.isData() && !f->second.dataVal.empty())
                return true;
        }
    }
    return false;
}

// Build the base download filename "<name> <version>" (no extension), matching
// iTunes, which names the file by the app's bundleDisplayName + a space + version
// and does NOT put the numeric id in it. The display name is preferred; bundleID
// is the fallback. Path-breaking characters in the name are replaced with '_'. The
// id is used only as a last resort when nothing else yields a name. Ext by callers.
static std::string build_base_filename(const std::string& displayName,
                                       const App& app, const std::string& version) {
    std::string front = !displayName.empty() ? displayName : app.bundleID;
    // Replace characters that are invalid in a Windows filename (and path
    // separators on any OS) with '_'; spaces are kept, as iTunes does.
    for (char& c : front)
        if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' ||
            c == '"' || c == '<'  || c == '>' || c == '|')
            c = '_';
    std::string name = front;
    if (!version.empty()) { if (!name.empty()) name += " "; name += version; }
    if (name.empty()) name = std::to_string(app.id);  // degenerate fallback only
    return name;
}

// Redownload refusal meaning this account holds no license for the item.
// Compared in full (Apple always sends these in English): other refusals with
// different wording have other causes and must not trigger a purchase.
static constexpr const char* REDOWNLOAD_UNAVAILABLE_MESSAGE =
    "Redownload Unavailable with This Apple Account";
static constexpr const char* REDOWNLOAD_UNAVAILABLE_EXPLANATION =
    "This redownload is not available for this Apple Account either because it "
    "was bought by a different user or the item was refunded or cancelled.";

// Apple writes "Apple Account" with a no-break space (U+00A0), which looks like
// a normal space in logs. Map Unicode spaces / tabs / newlines to ' ', collapse
// runs and trim, so the full phrases still compare exactly.
static std::string normalize_spaces(const std::string& in) {
    std::string out;
    bool pendingSpace = false;
    for (size_t i = 0; i < in.size(); ) {
        unsigned char c = (unsigned char)in[i];
        size_t len = 0;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')                 len = 1;
        else if (c == 0xC2 && i + 1 < in.size() && (unsigned char)in[i+1] == 0xA0) len = 2;  // U+00A0
        else if (c == 0xE2 && i + 2 < in.size() && (unsigned char)in[i+1] == 0x80) {
            unsigned char c2 = (unsigned char)in[i+2];
            if ((c2 >= 0x80 && c2 <= 0x8A) || c2 == 0xAF) len = 3;       // U+2000..200A, U+202F
        }
        if (len) { pendingSpace = true; i += len; continue; }
        if (pendingSpace && !out.empty()) out += ' ';
        pendingSpace = false;
        out += in[i++];
    }
    return out;
}

static bool is_redownload_unavailable(const PlistDict& d) {
    auto match = [](const PlistDict& m) {
        return normalize_spaces(dict_str(m, "message"))     == REDOWNLOAD_UNAVAILABLE_MESSAGE &&
               normalize_spaces(dict_str(m, "explanation")) == REDOWNLOAD_UNAVAILABLE_EXPLANATION;
    };
    if (match(d)) return true;
    auto it = d.find("dialog");   // Apple may nest them in a dialog dict
    return it != d.end() && it->second.isDict() && match(it->second.dictVal);
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Login
// ─────────────────────────────────────────────────────────────────────────────

Account AppStore::login(const std::string& email,
              const std::string& password,
              const std::string& authCode,
              const std::string& endpoint)
{
    std::string guid = get_guid();

    // Fetch bag for both the auth endpoint and SAP config
    BagOutput bag = fetch_bag(guid);
    std::string loginEndpoint = endpoint.empty() ? bag.authEndpoint : endpoint;

    // Create SAP signer — performs handshake with Apple servers (v2.4.0+).
    // Apple rejects unsigned authenticate requests and still counts them as
    // failed sign-ins (repeated failures lock the Apple ID), so any SAP problem
    // stops the login before a single request is sent — same as the Go version.
    if (bag.signSapSetup.empty() || bag.signSapSetupCert.empty()
        || bag.sapVersion != 200 || bag.hardwareID.empty())
        throw IpaError("bag has no usable SAP signing configuration; "
                       "refusing to send an unsigned login request");

    std::unique_ptr<SapSigner> signer;
    try {
        SapSigner::Config sapCfg;
        sapCfg.setupURL       = bag.signSapSetup;
        sapCfg.certificateURL = bag.signSapSetupCert;
        sapCfg.version        = bag.sapVersion;
        sapCfg.hardwareID     = bag.hardwareID;

        signer = SapSigner::Create(
            sapCfg,
            load_sap_asset("CoreFP"),
            load_sap_asset("CommerceCore"),
            load_sap_asset("CommerceKit"),
            load_sap_asset("CoreFP.icxs")
        );
    } catch (const std::exception& e) {
        throw IpaError(std::string("failed to initialize SAP signer: ") + e.what());
    }
    if (!signer)
        throw IpaError("failed to initialize SAP signer");
    if (m_debug) fprintf(stderr, "[DEBUG] SAP signer initialized OK\n");

    return do_login(email, password, authCode, guid, loginEndpoint, *signer);
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Search / Lookup
// ─────────────────────────────────────────────────────────────────────────────

AppStore::SearchOutput AppStore::search(const Account& acc, const std::string& term, int limit) {
    std::string cc  = country_code_from_storefront(acc.storeFront);
    std::string url = search_url(term, cc, limit);

    if (m_debug) debug_dump_request("search", "GET", url, {}, "");
    HttpResponse res = m_http.get(url);
    if (m_debug) debug_dump_response("search", res);
    if (res.statusCode != 200)
        throw IpaError("search request failed: " + std::to_string(res.statusCode));

    auto sr = parse_search_json(res.body);
    return {sr.count, sr.results};
}

App AppStore::lookup(const Account& acc, const std::string& bundleID) {
    std::string cc  = country_code_from_storefront(acc.storeFront);
    std::string url = lookup_url(bundleID, cc);

    if (m_debug) debug_dump_request("lookup", "GET", url, {}, "");
    HttpResponse res = m_http.get(url);
    if (m_debug) debug_dump_response("lookup", res);
    if (res.statusCode != 200)
        throw IpaError("lookup request failed: " + std::to_string(res.statusCode));

    auto sr = parse_search_json(res.body);
    if (sr.results.empty()) throw IpaError("app not found");
    return sr.results[0];
}

App AppStore::lookup_by_id(const Account& acc, int64_t appID) {
    std::string cc  = country_code_from_storefront(acc.storeFront);
    std::map<std::string, std::string> p = {
        {"entity",  "software,iPadSoftware"},
        {"limit",   "1"},
        {"media",   "software"},
        {"id",      std::to_string(appID)},
        {"country", cc},
    };
    std::string url = std::string("https://") + ITUNES_API_DOMAIN
                    + ITUNES_API_PATH_LOOKUP + "?" + build_query(p);

    if (m_debug) debug_dump_request("lookup-by-id", "GET", url, {}, "");
    HttpResponse res = m_http.get(url);
    if (m_debug) debug_dump_response("lookup-by-id", res);
    if (res.statusCode != 200)
        throw IpaError("lookup request failed: " + std::to_string(res.statusCode));

    auto sr = parse_search_json(res.body);
    if (sr.results.empty()) throw IpaError("app not found");
    return sr.results[0];
}

AppStore::ListPurchasesOutput AppStore::list_purchases(const Account& acc, int page,
                                                       const std::string& range) {
    // Pod-prefixed host, same scheme as buyProduct (p<pod>-buy.itunes.apple.com).
    std::string pod_prefix;
    if (!acc.pod.empty()) pod_prefix = "p" + acc.pod + "-";

    std::string url = "https://" + pod_prefix + std::string(PRIVATE_AS_DOMAIN)
                    + PRIVATE_AS_PATH_PURCHASES
                    + "?isDeepLink=false&isJsonApiFormat=true";
    // page omitted when <= 0 — the endpoint then tends to return everything in
    // one response; pass an explicit page only to fetch a specific later page.
    if (page > 0)
        url += "&page=" + std::to_string(page);
    // range selects the time window: default (omitted) = last 90 days,
    // "<year>-all" = that whole calendar year.
    if (!range.empty())
        url += "&range=" + url_encode(range);

    // Mirror the iTunes Purchase History request: session cookies (carried by
    // the shared jar) + X-Dsid + storefront + the Configurator UA. No anisette,
    // no X-Token. No Accept-Encoding, so the JSON comes back uncompressed and we
    // can read it directly.
    std::map<std::string, std::string> headers = {
        {"User-Agent",          CONFIGURATOR_UA},
        {"Accept-Language",     "en-us"},
        {"X-Apple-Store-Front", acc.storeFront},
        {"X-Dsid",              acc.directoryServicesID},
    };
    // The captured trace didn't carry X-Token (cookies + DSID authorize here),
    // but sending it too is harmless and covers the case where it's required.
    if (!acc.passwordToken.get().empty())
        headers["X-Token"] = acc.passwordToken.get();

    if (m_debug) debug_dump_request("list-purchases", "GET", url, headers, "");
    HttpResponse res = m_http.get(url, headers);
    if (m_debug) debug_dump_response("list-purchases", res);

    ListPurchasesOutput out;
    out.statusCode = res.statusCode;
    out.rawBody    = res.body;
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Purchase
// ─────────────────────────────────────────────────────────────────────────────

PlistDict AppStore::purchase(const Account& acc, const App& app) {
    if (app.price > 0.0) throw PaidAppNotSupported();

    std::string guid = get_guid();
    try {
        return do_purchase(acc, app, guid, PRICING_APPSTORE);
    } catch (const IpaError& e) {
        if (std::string(e.what()).find("temporarily unavailable") != std::string::npos) {
            return do_purchase(acc, app, guid, PRICING_ARCADE);
        } else {
            throw;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Download
// ─────────────────────────────────────────────────────────────────────────────

AppStore::DownloadOutput AppStore::download(const Account& acc,
                        const App& app,
                        const std::string& outputPath,
                        const std::string& externalVersionID,
                        ProgressCb progress,
                        const std::string& redownloadEndpoint,
                        const std::string& volumeStoreDownloadEndpoint,
                        const std::string& kbsyncB64,
                        const std::string& songDownloadDoneEndpoint)
{
    std::string guid = get_guid();
    m_regeneratedKbsync.clear();

    // Stateless 3-endpoint cascade (volumeStoreDownloadProduct → redownloadProduct
    // → updateProduct). Returns a served songList with sinf data, or throws
    // (LicenseRequired lets a --purchase caller acquire the license).
    PlistDict data = resolve_download(acc, app, guid, externalVersionID,
                                      redownloadEndpoint, volumeStoreDownloadEndpoint,
                                      kbsyncB64, /*isMac=*/false, /*needSinfs=*/true);
    auto songList = dict_arr(data, "songList");

    auto& itemVal = songList[0];
    if (!itemVal.isDict()) throw IpaError("invalid response: bad songList item");

    const PlistDict& item       = itemVal.dictVal;
    std::string      downloadURL = dict_str(item, "URL");
    std::string      md5Expected = dict_str(item, "md5");
    // download-id for the completion ping — comes from the same item as the URL
    // (usually empty, but can be populated), passed through verbatim.
    std::string      downloadId  = dict_str(item, "download-id");
    // songId for the completion ping; it equals the adamId, so fall back to it.
    int64_t          songId      = dict_int(item, "songId");
    if (songId == 0) songId = app.id;
    std::string      version     = "unknown";

    auto metaIt  = item.find("metadata");
    PlistDict metadata;
    if (metaIt != item.end() && metaIt->second.isDict()) {
        metadata = metaIt->second.dictVal;
        auto vIt = metadata.find("bundleShortVersionString");
        if (vIt != metadata.end() && vIt->second.isString())
            version = vIt->second.str();
    }
    // iTunes names downloads by bundleDisplayName — always present in the response
    // metadata (iOS and macOS), so numeric-id downloads (no catalog lookup) still
    // get a name. build_base_filename falls back to bundleID if it were ever empty.
    std::string displayName = dict_str(metadata, "bundleDisplayName");

    std::vector<Sinf> sinfs;
    auto sinfsIt = item.find("sinfs");
    if (sinfsIt != item.end() && sinfsIt->second.isArray()) {
        for (auto& sv : sinfsIt->second.arrayVal) {
            if (!sv.isDict()) continue;
            Sinf s;
            s.id = dict_int(sv.dictVal, "id");
            auto dit = sv.dictVal.find("sinf");
            // dpInfo — macOS decryption key
            auto dpit = sv.dictVal.find("dpInfo");
            if (dpit != sv.dictVal.end() && dpit->second.isData())
                s.dpInfo = dpit->second.dataVal;
            if (dit != sv.dictVal.end() && dit->second.isData())
                s.data = dit->second.dataVal;
            sinfs.push_back(std::move(s));
        }
    }

    // Verify the finished raw download against the store's md5, then report the
    // completion to Apple. Called on the raw downloaded temp file (before any
    // repack/decrypt), since the md5 describes the file exactly as served.
    auto verify_and_report = [&](const std::string& rawTmpPath) {
        if (!md5Expected.empty()) {
            std::string actual = md5_file_hex(rawTmpPath);
            if (actual.empty())
                throw IpaError("could not compute md5 of downloaded file");
            if (m_debug)
                fprintf(stderr, "[DEBUG] md5 check: expected=%s actual=%s\n",
                        md5Expected.c_str(), actual.c_str());

            if (!ascii_iequals(actual, md5Expected)) {
                // download() only returns on a fully received transfer (curl
                // CURLE_OK; short reads are retried), so a mismatch here means a
                // complete-but-corrupt file — safe to discard. Re-download once
                // from scratch (remove → rangeStart 0 → full GET) and re-check.
                if (m_debug)
                    fprintf(stderr, "[DEBUG] md5 mismatch — discarding and re-downloading once\n");
                fs::remove(ipt::fs_path(rawTmpPath));
                m_http.download(downloadURL, rawTmpPath, 0, progress);

                actual = md5_file_hex(rawTmpPath);
                if (m_debug)
                    fprintf(stderr, "[DEBUG] md5 recheck: expected=%s actual=%s\n",
                            md5Expected.c_str(), actual.c_str());
                if (!ascii_iequals(actual, md5Expected)) {
                    // Still bad — leave no corrupt .tmp behind so a manual re-run
                    // starts clean instead of resuming onto garbage.
                    fs::remove(ipt::fs_path(rawTmpPath));
                    throw IpaError("download hash mismatch after re-download (expected md5 " +
                                   md5Expected + ", got " + actual + ")");
                }
            }
        } else if (m_debug) {
            fprintf(stderr, "[DEBUG] no md5 in response — skipping hash verification\n");
        }
        // Completion ping is best-effort: a failure here must not invalidate the
        // file we already downloaded and verified.
        if (!songDownloadDoneEndpoint.empty()) {
            try {
                bool ok = report_download_done(acc, songId, downloadId, songDownloadDoneEndpoint);
                if (m_debug)
                    fprintf(stderr, "[DEBUG] songDownloadDone: %s\n",
                            ok ? "success reported" : "no success marker in response");
            } catch (const std::exception& e) {
                if (m_debug) fprintf(stderr, "[DEBUG] songDownloadDone request failed: %s\n", e.what());
            }
        }
    };

    // ── macOS .pkg detection ───────────────────────────────────────────────────
    // Detect by URL extension or metadata software-platform.
    // pkg files must NOT go through minizip/apply_patches (they are XAR archives).
    bool isMacPkg = (downloadURL.size() >= 4 &&
                     downloadURL.substr(downloadURL.size()-4) == ".pkg");
    if (!isMacPkg) {
        auto platIt = metadata.find("software-platform");
        if (platIt != metadata.end() && platIt->second.isString() &&
            platIt->second.strVal == "macos")
            isMacPkg = true;
    }

    if (isMacPkg) {
        // Collect dpInfo from sinfs (may be empty for unencrypted apps)
        std::vector<uint8_t> dpInfo;
        for (auto& s : sinfs) {
            if (!s.dpInfo.empty()) { dpInfo = s.dpInfo; break; }
        }

        // Resolve output path exactly like the iOS path: -o as a file is used
        // verbatim, a directory gets "{name} {version}.pkg", empty defaults to the
        // current directory. (Unicode-safe; no blind ".pkg" appending.)
        std::string pkgDest = resolve_destination(app, version, outputPath, displayName, ".pkg");

        std::string tmpPkg = pkgDest + ".tmp";
        int64_t rangeStart = file_size(tmpPkg);
        m_http.download(downloadURL, tmpPkg, rangeStart, progress);

        verify_and_report(tmpPkg);

        if (dpInfo.empty()) {
            // Unencrypted (drmVersionNumber=0) — rename directly
            if (m_debug) fprintf(stderr, "[DEBUG] macOS pkg is unencrypted, saving directly\n");
            std::error_code ec;
            fs::rename(ipt::fs_path(tmpPkg), ipt::fs_path(pkgDest), ec);
            if (ec) {
                fs::copy_file(ipt::fs_path(tmpPkg), ipt::fs_path(pkgDest),
                              fs::copy_options::overwrite_existing, ec);
                fs::remove(ipt::fs_path(tmpPkg), ec);
                if (ec) throw IpaError("failed to save pkg: " + ec.message());
            }
        } else {
            // Encrypted — StoreAgent decrypt
            if (m_debug)
                fprintf(stderr, "[DEBUG] macOS pkg encrypted, dpInfo=%zu bytes\n", dpInfo.size());
            auto hardwareID = SapSigner::LocalHardwareID();
            auto machine = StoreAgentMachine::Create(
                load_sap_asset("CoreFP"),
                load_sap_asset("CommerceCore"),
                load_sap_asset("CommerceKit"),
                load_sap_asset("CoreFP.icxs"),
                load_sap_asset("storeagent")
            );
            uint32_t gctx    = machine->InitializeGlobal(hardwareID);
            uint64_t session = machine->InitializeSession(gctx, dpInfo);

            std::string decTmp = pkgDest + ".dec";
            {
                std::ifstream src_f(ipt::fs_path(tmpPkg), std::ios::binary);
                std::ofstream dst_f(ipt::fs_path(decTmp), std::ios::binary | std::ios::trunc);
                if (!src_f) throw IpaError("cannot open encrypted pkg");
                if (!dst_f) throw IpaError("cannot open decrypted pkg output");
                std::vector<uint8_t> buf(StoreAgentMachine::kChunkSize);
                while (true) {
                    src_f.read(reinterpret_cast<char*>(buf.data()), buf.size());
                    std::streamsize n = src_f.gcount();
                    if (n == 0) break;
                    std::span<uint8_t> chunk(buf.data(), static_cast<size_t>(n));
                    machine->DecryptChunk(session, chunk);
                    dst_f.write(reinterpret_cast<const char*>(chunk.data()), n);
                }
            }
            machine->CloseSession(session);
            fs::remove(ipt::fs_path(tmpPkg));
            std::error_code ec;
            fs::rename(ipt::fs_path(decTmp), ipt::fs_path(pkgDest), ec);
            if (ec) { fs::copy_file(ipt::fs_path(decTmp), ipt::fs_path(pkgDest), fs::copy_options::overwrite_existing); fs::remove(ipt::fs_path(decTmp)); }
        }
        return { pkgDest, sinfs };
    }

    // ── iOS IPA path ────────────────────────────────────────────────────────
    std::string dest    = resolve_destination(app, version, outputPath, displayName);
    std::string tmpDest = dest + ".tmp";

    int64_t rangeStart = file_size(tmpDest);
    m_http.download(downloadURL, tmpDest, rangeStart, progress);

    verify_and_report(tmpDest);

    apply_patches(item, acc, tmpDest, dest, sinfs);
    fs::remove(ipt::fs_path(tmpDest));

    return {dest, sinfs};
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — List Versions / Get Version Metadata
// ─────────────────────────────────────────────────────────────────────────────

AppStore::ListVersionsOutput AppStore::list_versions(const Account& acc,
                        const App& app,
                        const std::string& redownloadEndpoint,
                        const std::string& volumeStoreDownloadEndpoint,
                        const std::string& kbsyncB64)
{
    std::string guid = get_guid();
    m_regeneratedKbsync.clear();

    // Stateless 3-endpoint cascade; list-versions needs only item metadata, so
    // sinf data is not required (needSinfs=false).
    PlistDict data = resolve_download(acc, app, guid, /*externalVersionID=*/"",
                                      redownloadEndpoint, volumeStoreDownloadEndpoint,
                                      kbsyncB64, /*isMac=*/false, /*needSinfs=*/false);
    auto songList = dict_arr(data, "songList");
    {
    auto& itemVal = songList[0];
    if (!itemVal.isDict()) throw IpaError("invalid response: bad songList item");
    const PlistDict& item = itemVal.dictVal;

    auto metaIt = item.find("metadata");
    if (metaIt == item.end() || !metaIt->second.isDict())
        throw IpaError("failed to get version identifiers from item metadata");
    const PlistDict& metadata = metaIt->second.dictVal;

    // softwareVersionExternalIdentifiers — array of version IDs
    ListVersionsOutput out;
    auto idsIt = metadata.find("softwareVersionExternalIdentifiers");
    if (idsIt == metadata.end() || !idsIt->second.isArray())
        throw IpaError("failed to get version identifiers from item metadata");
    for (auto& v : idsIt->second.arrayVal)
        out.externalVersionIdentifiers.push_back(v.isInt()
            ? std::to_string(v.intVal) : v.str());

    // softwareVersionExternalIdentifier — latest version
    auto latIt = metadata.find("softwareVersionExternalIdentifier");
    if (latIt == metadata.end())
        throw IpaError("failed to get latest version from item metadata");
    out.latestExternalVersionID = latIt->second.isInt()
        ? std::to_string(latIt->second.intVal) : latIt->second.str();

    return out;
    } // version-identifier extraction block
}

AppStore::GetVersionMetadataOutput AppStore::get_version_metadata(const Account& acc,
                                               const App& app,
                                               const std::string& versionID,
                                               const std::string& redownloadEndpoint,
                                               const std::string& volumeStoreDownloadEndpoint,
                                               const std::string& kbsyncB64)
{
    std::string guid = get_guid();
    m_regeneratedKbsync.clear();

    // Stateless 3-endpoint cascade; get-version-metadata needs only item metadata.
    PlistDict data = resolve_download(acc, app, guid, versionID,
                                      redownloadEndpoint, volumeStoreDownloadEndpoint,
                                      kbsyncB64, /*isMac=*/false, /*needSinfs=*/false);
    auto songList = dict_arr(data, "songList");
    auto& itemVal = songList[0];
    if (!itemVal.isDict()) throw IpaError("invalid response: bad songList item");
    const PlistDict& item = itemVal.dictVal;

    auto metaIt = item.find("metadata");
    if (metaIt == item.end() || !metaIt->second.isDict())
        throw IpaError("failed to get metadata from item");
    const PlistDict& metadata = metaIt->second.dictVal;

    GetVersionMetadataOutput out;
    auto dvIt = metadata.find("bundleShortVersionString");
    if (dvIt != metadata.end()) out.displayVersion = dvIt->second.str();
    auto rdIt = metadata.find("releaseDate");
    if (rdIt != metadata.end()) out.releaseDate = rdIt->second.str();

    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Private: misc / kbsync
// ─────────────────────────────────────────────────────────────────────────────

// GUID sent with every App Store request: hex of the physical adapter's MAC
// (device_mac.cpp). Throws IpaError when no real address is available, so no
// request ever goes out with a placeholder device ID.
std::string AppStore::get_guid() {
    return device_guid();
}

void AppStore::set_debug(bool v) {
    m_debug = v;
    m_http.set_debug(v);
    SapSigner::SetDebug(v);
    device_mac_set_debug(v);
}

std::vector<uint8_t> AppStore::generate_kbsync(uint64_t dsid) {
    // Same hardware identity as the GUID sent with every request.
    auto hardwareID = device_mac_address();

    // FairPlay's global-context init is heavy (~20 s on a fast host, longer on
    // a slow Unicorn build). Warn so a --debug run doesn't look frozen.
    if (m_debug)
        fprintf(stderr, "[DEBUG] kbsync: generating via FairPlay emulation, "
                        "this can take up to a minute...\n");

    auto machine = StoreAgentMachine::Create(
        load_sap_asset("CoreFP"),
        load_sap_asset("CommerceCore"),
        load_sap_asset("CommerceKit"),
        load_sap_asset("CoreFP.icxs"),
        load_sap_asset("storeagent"));

    uint32_t ctx = machine->InitializeGlobal(hardwareID);
    if (m_debug)
        fprintf(stderr, "[DEBUG] kbsync: FairPlay global context %u\n", ctx);

    auto kbsync = machine->KBSyncData(ctx, dsid);
    if (m_debug)
        fprintf(stderr, "[DEBUG] kbsync: %zu bytes for DSID %llu\n",
                kbsync.size(), static_cast<unsigned long long>(dsid));
    return kbsync;
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Private: download endpoints, cascade & bag
// ─────────────────────────────────────────────────────────────────────────────

// ── Device serial (fserial) for volumeStoreDownloadProduct ──────────────────
// Device serial for volumeStoreDownload: 9 bytes (54 C8 B0 A9 88 + last 4 bytes of the
// GUID), base64-encoded. Unique per machine. guid is 12 hex chars (6 bytes).
static std::string make_fserial(const std::string& guid) {
    std::vector<uint8_t> bytes = { 0x54, 0xC8, 0xB0, 0xA9, 0x88 };
    std::string tail = guid.size() >= 8 ? guid.substr(guid.size() - 8) : guid;
    for (size_t i = 0; i + 1 < tail.size(); i += 2) {
        try { bytes.push_back((uint8_t)std::stoul(tail.substr(i, 2), nullptr, 16)); }
        catch (...) { break; }
    }
    return SapBase64::Encode(bytes);
}

// ── volumeStoreDownloadProduct (bag download endpoint, kbsync-signed) ───────
PlistDict AppStore::volume_store_download_product(const Account& acc, const App& app,
                                      const std::string& guid,
                                      const std::string& volumeStoreDownloadEndpoint,
                                      const std::string& kbsyncB64,
                                      const std::string& externalVersionID,
                                      bool authed,
                                      int& httpStatus)
{
    httpStatus = 0;
    std::string url = volumeStoreDownloadEndpoint + "?guid=" + guid;

    // Headers match the reference tool exactly (note: form-urlencoded content
    // type even though the body is a plist, plus an explicit Configurator UA).
    std::map<std::string, std::string> hdrs = {
        {"Content-Type",        "application/x-www-form-urlencoded; charset=utf-8"},
        {"User-Agent",          "Configurator/2.18 (Macintosh; OS X 15.3.2; 24D81) "
                                "AppleWebKit/0620.2.4.11.6"},
        {"iCloud-DSID",         acc.directoryServicesID},
        {"X-Dsid",              acc.directoryServicesID},
        {"X-Apple-Store-Front", acc.storeFront},
        {"X-Token",             acc.passwordToken.get()},
    };

    PlistDict p;
    p["creditDisplay"] = PlistValue::makeString("");
    p["guid"]          = PlistValue::makeString(guid);
    p["kbsync"]        = PlistValue::makeString(kbsyncB64);
    p["salableAdamId"] = PlistValue::makeString(std::to_string(app.id));
    // Fall back to computing the serial from the GUID for accounts saved before
    // fserial existed (it is deterministic, so this equals the login-time value).
    p["serialNumber"]  = PlistValue::makeString(
        acc.fserial.empty() ? make_fserial(guid) : acc.fserial);
    if (!externalVersionID.empty())
        p["externalVersionId"] = PlistValue::makeString(externalVersionID);
    // 2042 AuthTokenResumeFreeBuy confirmation ("Download" in the dialog).
    if (authed)
        p["hasBeenAuthedForBuy"] = PlistValue::makeString("true");

    std::string body = encode_plist_xml(p);
    if (m_debug) debug_dump_request("volumeStoreDownload", "POST", url, hdrs, body);
    HttpResponse res = m_http.post(url, body, hdrs);
    httpStatus = res.statusCode;
    if (m_debug) debug_dump_response("volumeStoreDownload", res);
    return decode_plist(res.body);
}

// Report a completed download to Apple via the bag's songDownloadDone URL.
// The host gets the account pod prefix (p<pod>-…) and the query carries songId
// (= adamId), an empty download-id, the pod, and the request guid. GET only —
// just cookies + headers, no body. Success = jingleDocType "success".
bool AppStore::report_download_done(const Account& acc, int64_t songId,
                                    const std::string& downloadId,
                                    const std::string& songDownloadDoneEndpoint)
{
    if (songDownloadDoneEndpoint.empty()) return false;
    std::string guid = get_guid();

    // Inject the pod prefix right after the scheme:
    //   https://buy.itunes.apple.com/… → https://p<pod>-buy.itunes.apple.com/…
    std::string url = songDownloadDoneEndpoint;
    if (!acc.pod.empty()) {
        auto pos = url.find("://");
        if (pos != std::string::npos)
            url.insert(pos + 3, "p" + acc.pod + "-");
    }
    url += "?songId="       + std::to_string(songId)
         + "&download-id="  + downloadId
         + "&Pod="          + acc.pod
         + "&guid="         + guid;

    // Same shape as volume_store_download_product, minus X-Token; GET carries no body.
    // Accept-Encoding is intentionally omitted — curl does not auto-decompress
    // a manually requested gzip, and the plist response is tiny anyway.
    std::map<std::string, std::string> hdrs = {
        {"User-Agent",          "Configurator/2.18 (Macintosh; OS X 15.3.2; 24D81) "
                                "AppleWebKit/0620.2.4.11.6"},
        {"Accept",              "*/*"},
        {"Accept-Language",     "en-US"},
        {"iCloud-DSID",         acc.directoryServicesID},
        {"X-Dsid",              acc.directoryServicesID},
        {"X-Apple-Store-Front", acc.storeFront},
    };

    if (m_debug) debug_dump_request("songDownloadDone", "GET", url, hdrs, "");
    HttpResponse res = m_http.get(url, hdrs);
    if (m_debug) debug_dump_response("songDownloadDone", res);

    if (res.statusCode != 200) return false;
    // jingleDocType success — tolerant to plist whitespace/formatting.
    return res.body.find("<string>success</string>") != std::string::npos;
}


// ── Redownload / updateProduct (port of upstream appstore_download_product.go)

static std::string trim_copy(const std::string& v) {
    size_t b = v.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = v.find_last_not_of(" \t\r\n");
    return v.substr(b, e - b + 1);
}

static std::string plist_scalar_str(const PlistDict& d, const std::string& key) {
    auto it = d.find(key);
    if (it == d.end()) return "";
    return it->second.isInt() ? std::to_string(it->second.intVal) : it->second.str();
}

// Upstream isUnavailableDownloadProductResponse: 200, no failureType, no items,
// customerMessage "No Longer Available" (optionally prefixed).
static bool is_unavailable_response(int statusCode, const PlistDict& d) {
    if (statusCode != 200 || !dict_str(d, "failureType").empty()
        || !dict_arr(d, "songList").empty())
        return false;
    std::string m = trim_copy(dict_str(d, "customerMessage"));
    std::transform(m.begin(), m.end(), m.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    static const std::string kSuffix = " no longer available";
    return m == "no longer available"
        || (m.size() > kSuffix.size()
            && m.compare(m.size() - kSuffix.size(), kSuffix.size(), kSuffix) == 0);
}

// Decode a response body; an empty or non-plist body yields an empty dict.
static PlistDict decode_plist_safe(const std::string& body) {
    if (trim_copy(body).empty()) return {};
    try { return decode_plist(body); } catch (...) { return {}; }
}

// Headers and payload shared by the downloadProduct-family requests
// (redownloadProduct, updateProduct).
static std::map<std::string, std::string> download_request_headers(const Account& acc) {
    return {
        {"Content-Type", "application/x-apple-plist"},
        {"iCloud-DSID",  acc.directoryServicesID},
        {"X-Dsid",       acc.directoryServicesID},
    };
}

static std::string download_request_payload(const std::string& guid, const App& app,
                                            const std::string& appExtVrsId) {
    PlistDict p;
    p["creditDisplay"] = PlistValue::makeString("");
    p["guid"]          = PlistValue::makeString(guid);
    p["salableAdamId"] = PlistValue::makeInt(app.id);
    p["serialNumber"]  = PlistValue::makeString("0");
    if (!appExtVrsId.empty())
        p["appExtVrsId"] = PlistValue::makeString(appExtVrsId);
    return encode_plist_xml(p);
}

// ── resolve_download — stateless 3-endpoint cascade ─────────────────────────
// We keep no local library state, so we cannot know up front which endpoint owns
// the app. We try all three bag endpoints in order and take the first that serves:
//   1) volumeStoreDownloadProduct (kbsync)  — the modern primary path
//   2) redownloadProduct                    — re-acquire from purchase history
//   3) updateProduct                        — library / update dispatch
// "served" means a songList item is present — with sinf data when the caller must
// decrypt (download), or just metadata when it need not (list-versions,
// get-version-metadata). If none serves and the account simply has no license, we
// throw LicenseRequired so a --purchase caller can acquire it.
PlistDict AppStore::resolve_download(const Account& acc, const App& app,
                                     const std::string& guid,
                                     const std::string& externalVersionID,
                                     const std::string& redownloadEndpoint,
                                     const std::string& volumeStoreDownloadEndpoint,
                                     const std::string& kbsyncB64,
                                     bool isMac, bool needSinfs)
{
    auto served = [&](const PlistDict& d) {
        auto sl = dict_arr(d, "songList");
        if (sl.empty()) return false;
        return needSinfs ? has_sinfs(sl) : true;
    };
    // failureType, falling back to metrics.messageCode (Apple wraps 2042 there).
    auto failure_of = [](const PlistDict& d) {
        std::string ft = dict_str(d, "failureType");
        if (ft.empty()) {
            auto it = d.find("metrics");
            if (it != d.end() && it->second.isDict())
                ft = dict_str(it->second.dictVal, "messageCode");
        }
        return ft;
    };

    PlistDict   vsData;          // step-1 response, kept for final error mapping
    std::string vsFailure;
    std::string customerMessage; // best-effort message for the final error

    // ── 1) volumeStoreDownloadProduct (bag, kbsync) ─────────────────────────
    if (!volumeStoreDownloadEndpoint.empty() && !kbsyncB64.empty()) {
        std::string kb = kbsyncB64;               // may be swapped for a fresh blob below
        int st = 0;
        vsData = volume_store_download_product(acc, app, guid, volumeStoreDownloadEndpoint,
                                               kb, externalVersionID,
                                               /*authed=*/false, st);
        if (served(vsData)) return vsData;

        // HTTP >= 500 here means the kbsync blob was rejected (it is bound to
        // DSID + hardwareID and goes stale). Regenerate it ONCE and retry this
        // endpoint right away with the fresh blob — a stale kbsync shouldn't cost
        // a whole second run. The fresh blob is handed to the caller to cache.
        // If the retry is still >= 500 the kbsync is fresh, so it is not the
        // problem: we stop retrying here and fall through to the cascade with the
        // same failure handling as the first attempt.
        if (st >= 500) {
            try {
                uint64_t dsid = std::stoull(acc.directoryServicesID);
                std::string fresh = SapBase64::Encode(generate_kbsync(dsid));
                if (!fresh.empty()) {
                    m_regeneratedKbsync = fresh;   // caller caches this instead of clearing
                    kb = fresh;
                    if (m_debug)
                        fprintf(stderr, "[DEBUG] volumeStoreDownload HTTP %d — regenerated kbsync, retrying\n", st);
                    int stR = 0;
                    vsData = volume_store_download_product(acc, app, guid, volumeStoreDownloadEndpoint,
                                                           kb, externalVersionID,
                                                           /*authed=*/false, stR);
                    if (served(vsData)) return vsData;
                    st = stR;                      // keep handling errors on the retry response
                }
            } catch (const std::exception& e) {
                if (m_debug) fprintf(stderr, "[DEBUG] kbsync regeneration failed (%s)\n", e.what());
            }
        }

        vsFailure = failure_of(vsData);

        // 2042 AuthTokenResumeFreeBuy → one retry with hasBeenAuthedForBuy
        // (equivalent of clicking "Download" in the confirmation dialog).
        if (vsFailure == FAILURE_SIGN_IN_REQUIRED) {
            auto dit = vsData.find("dialog");
            bool authDialog = (dit != vsData.end() && dit->second.isDict() &&
                               dict_str(dit->second.dictVal, "kind") == "authorization");
            if (authDialog) {
                if (m_debug)
                    fprintf(stderr, "[DEBUG] volumeStoreDownload auth dialog — retrying with hasBeenAuthedForBuy\n");
                int st2 = 0;
                vsData = volume_store_download_product(acc, app, guid, volumeStoreDownloadEndpoint,
                                                       kb, externalVersionID,
                                                       /*authed=*/true, st2);
                if (served(vsData)) return vsData;
                vsFailure = failure_of(vsData);
            }
        }
        // A token / sign-in / device-verification failure is a session issue, not a
        // missing license: surface it so the caller re-logs-in.
        if (vsFailure == FAILURE_PASSWORD_TOKEN_EXPIRED ||
            vsFailure == FAILURE_SIGN_IN_REQUIRED       ||
            vsFailure == FAILURE_DEVICE_VERIFICATION)
            throw PasswordTokenExpired();
        if (dict_str(vsData, "customerMessage") == CUSTOMER_MSG_SIGN_IN)
            throw PasswordTokenExpired();
        if (!dict_str(vsData, "customerMessage").empty())
            customerMessage = dict_str(vsData, "customerMessage");
    }

    // Version pin, shared by redownload and updateProduct (empty = unpinned).
    std::string pin = isMac ? externalVersionID
                            : redownload_version_id(acc, app, externalVersionID);

    // ── 2) redownloadProduct, then 3) updateProduct ─────────────────────────
    bool rdUnavailable = false;
    if (!redownloadEndpoint.empty()) {
        int rdStatus = 0;
        PlistDict rd = redownload_product(acc, app, guid, redownloadEndpoint,
                                          pin, "redownloadProduct", rdStatus);
        if (served(rd)) return rd;

        rdUnavailable = (rdStatus != 500 && is_redownload_unavailable(rd));
        if (!dict_str(rd, "customerMessage").empty())
            customerMessage = dict_str(rd, "customerMessage");

        // Try updateProduct whenever redownload did not serve: an empty HTTP 500,
        // a "No Longer Available" message, an "unavailable" dialog, a download
        // without sinf data, or simply an empty songList. We run the full cascade
        // regardless, since without library state we cannot know the entitlement.
        bool wantUpdate = (rdStatus == 500 && rd.empty())
                       || is_unavailable_response(rdStatus, rd)
                       || rdUnavailable
                       || (needSinfs && rdStatus == 200 && dict_str(rd, "failureType").empty()
                           && !has_sinfs(dict_arr(rd, "songList")))
                       || (!needSinfs && dict_arr(rd, "songList").empty());

        if (wantUpdate && !pin.empty() && !m_updateEndpoint.empty()) {
            if (m_debug)
                fprintf(stderr, "[DEBUG] redownloadProduct did not serve — trying updateProduct\n");
            try {
                PlistDict up = update_product(acc, app, guid, pin);
                if (served(up)) return up;
                if (!dict_str(up, "customerMessage").empty())
                    customerMessage = dict_str(up, "customerMessage");
                // updateProduct returned a structured failure without items.
                if (rdUnavailable) throw LicenseRequired();
            } catch (const PasswordTokenExpired&) {
                throw;                       // session issue — must re-login
            } catch (const LicenseRequired&) {
                throw;                       // keep the license signal for --purchase
            } catch (const IpaError& e) {
                // updateProduct refused/errored. If redownload had already said the
                // item is unavailable for this account, that is a missing license.
                if (rdUnavailable) throw LicenseRequired();
                if (customerMessage.empty()) customerMessage = e.what();
            }
        } else if (rdUnavailable) {
            throw LicenseRequired();
        }
    }

    // ── Nothing served: map to the exception the caller expects ─────────────
    if (vsFailure == FAILURE_LICENSE_NOT_FOUND) throw LicenseRequired();
    if (!customerMessage.empty())               throw IpaError(customerMessage);
    if (dict_str(vsData, "jingleDocType") == "purchaseSuccess")
        throw IpaError("app is not available for download in your region/storefront"
                       " (license was granted but download was blocked)");
    if (!vsFailure.empty())                     throw IpaError("received error: " + vsFailure);
    throw IpaError("invalid response: empty songList");
}

// ── redownloadProduct (bag) — re-acquire from the account's purchase history.
// Pure endpoint call: POST, decode, return the response and its HTTP status. The
// cascade decisions (whether to fall on to updateProduct, when to conclude a
// missing license) live in resolve_download. `pin` is the version id, computed by
// the caller (empty = unpinned).
PlistDict AppStore::redownload_product(const Account& acc, const App& app,
                                       const std::string& guid,
                                       const std::string& redownloadEndpoint,
                                       const std::string& pin,
                                       const char* label,
                                       int& httpStatus)
{
    httpStatus = 0;
    auto        hdrs = download_request_headers(acc);
    std::string body = download_request_payload(guid, app, pin);
    std::string url  = redownloadEndpoint + "?guid=" + guid;

    if (m_debug) debug_dump_request(label, "POST", url, hdrs, body);
    HttpResponse res = m_http.post(url, body, hdrs);
    httpStatus = res.statusCode;
    if (m_debug) debug_dump_response(label, res);

    return decode_plist_safe(res.body);
}

PlistDict AppStore::update_product(const Account& acc, const App& app,
                                        const std::string& guid,
                                        const std::string& externalVersionID)
{
    // updateProduct endpoint comes straight from the bag (resolve_download only
    // calls this when it is non-empty) — trusted like every other bag endpoint.
    auto        hdrs = download_request_headers(acc);
    std::string body = download_request_payload(guid, app, externalVersionID);
    std::string url  = m_updateEndpoint + "?guid=" + guid;

    if (m_debug) debug_dump_request("updateProduct", "POST", url, hdrs, body);
    HttpResponse res = m_http.post(url, body, hdrs);
    if (m_debug) debug_dump_response("updateProduct", res);

    PlistDict data = decode_plist_safe(res.body);

    // Structured failures keep their normal handling in the caller.
    if (!dict_str(data, "failureType").empty())
        return data;

    std::string customerMessage = dict_str(data, "customerMessage");
    if (!customerMessage.empty())
        throw IpaError("received update error: " + customerMessage);

    if (res.statusCode != 200)
        throw IpaError("received unexpected update status code: "
                       + std::to_string(res.statusCode));

    auto items = dict_arr(data, "songList");
    if (items.size() != 1 || !items[0].isDict())
        throw IpaError("update response must contain exactly one item");

    auto metaIt = items[0].dictVal.find("metadata");
    if (metaIt == items[0].dictVal.end() || !metaIt->second.isDict())
        throw IpaError("update response does not match the requested app or version");
    const PlistDict& meta = metaIt->second.dictVal;

    if (plist_scalar_str(meta, "itemId") != std::to_string(app.id) ||
        plist_scalar_str(meta, "softwareVersionExternalIdentifier") != externalVersionID)
        throw IpaError("update response does not match the requested app or version");

    std::string bundleID = dict_str(meta, "softwareVersionBundleId");
    if (bundleID.empty() || (!app.bundleID.empty() && bundleID != app.bundleID))
        throw IpaError("update response does not match the requested bundle identifier");

    return data;
}

// ── Platform version lookup ──────────────────────────────────────────────
// Port of upstream pkg/appstore/appstore_platform_version_lookup.go,
// including e5211d6 "fall back to consumer catalogs for ios version lookup".

// externalId may arrive as a JSON string or number (upstream UnmarshalJSON).
static std::string platform_external_id_to_string(const json& v) {
    if (v.is_string())          return v.get<std::string>();
    if (v.is_number_unsigned()) return std::to_string(v.get<uint64_t>());
    if (v.is_number_integer())  return std::to_string(v.get<int64_t>());
    if (v.is_null())            return "";
    throw IpaError("invalid external version id " + v.dump());
}

// buyParams is a query string: "...&appExtVrsId=123456&..."
static std::string external_version_id_from_buy_params(const std::string& buyParams) {
    std::istringstream ss(buyParams);
    std::string kv;
    while (std::getline(ss, kv, '&')) {
        auto eq = kv.find('=');
        if (eq != std::string::npos && kv.compare(0, eq, "appExtVrsId") == 0)
            return kv.substr(eq + 1);
    }
    return "";
}

std::string AppStore::lookup_latest_external_version_id(const Account& acc, const App& app) {
    if (app.id == 0)
        throw IpaError("app ID is required for platform version lookup");

    std::string cc = country_code_from_storefront(acc.storeFront);
    std::transform(cc.begin(), cc.end(), cc.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });

    // Some storefronts have no enterprise listing even when the consumer
    // catalogs contain the app. Keep the account's country for each lookup.
    static const char* const kCatalogs[] = { "enterprisestore", "iphone", "ipad" };

    const std::string appKey = std::to_string(app.id);
    std::string lastErr;

    for (const char* catalog : kCatalogs) {
        std::map<std::string, std::string> p = {
            {"version",  "2"},
            {"id",       appKey},
            {"p",        "mdm-lockup"},
            {"caller",   "MDM"},
            {"platform", catalog},
            {"cc",       cc},
            {"l",        "en"},
        };
        std::string url = "https://uclient-api.itunes.apple.com/WebObjects/"
                          "MZStorePlatform.woa/wa/lookup?" + build_query(p);

        HttpResponse res = m_http.get(url);
        if (m_debug)
            fprintf(stderr, "[DEBUG] platform version lookup (%s) status: %d\n",
                    catalog, res.statusCode);
        if (res.statusCode != 200)
            throw IpaError("platform version lookup request failed: "
                           + std::to_string(res.statusCode));

        json j = json::parse(res.body, nullptr, /*allow_exceptions=*/false);
        if (j.is_discarded())
            throw IpaError("platform version lookup returned invalid JSON");

        const json* item = nullptr;
        auto rIt = j.find("results");
        if (rIt != j.end() && rIt->is_object()) {
            auto aIt = rIt->find(appKey);
            if (aIt != rIt->end() && aIt->is_object()) item = &*aIt;
        }
        if (!item) {
            lastErr = "platform version lookup returned no app";
            continue;
        }

        auto oIt = item->find("offers");
        if (oIt == item->end() || !oIt->is_array() || oIt->empty()
            || !(*oIt)[0].is_object()) {
            lastErr = "platform version lookup returned no offers";
            continue;
        }
        const json& offer = (*oIt)[0];

        std::string externalVersionID;
        auto vIt = offer.find("version");
        if (vIt != offer.end() && vIt->is_object()) {
            auto eIt = vIt->find("externalId");
            if (eIt != vIt->end())
                externalVersionID = platform_external_id_to_string(*eIt);
        }
        if (externalVersionID.empty()) {
            auto bIt = offer.find("buyParams");
            if (bIt != offer.end() && bIt->is_string())
                externalVersionID = external_version_id_from_buy_params(bIt->get<std::string>());
        }
        if (externalVersionID.empty())
            throw IpaError("platform version lookup returned no external version id");

        if (m_debug)
            fprintf(stderr, "[DEBUG] platform version lookup (%s): externalVersionId=%s\n",
                    catalog, externalVersionID.c_str());
        return externalVersionID;
    }

    throw IpaError("app " + appKey + " in storefront " + cc
                   + " (catalogs: enterprisestore, iphone, ipad): " + lastErr);
}

std::string AppStore::redownload_version_id(const Account& acc, const App& app,
                                            const std::string& externalVersionID) {
    if (!externalVersionID.empty()) return externalVersionID;
    try {
        return lookup_latest_external_version_id(acc, app);
    } catch (const std::exception& e) {
        // Upstream aborts here; we keep the previous unpinned redownload so
        // apps that already worked are not broken by a lookup failure.
        if (m_debug)
            fprintf(stderr, "[DEBUG] %s — sending unpinned redownload\n", e.what());
        return "";
    }
}

// ── Bag (fetch bag.xml: all download/auth endpoints + SAP config) ───────────

// Fetch and parse bag.xml. Called with no guid by external callers (uses
// get_guid()); login() passes its own guid so the whole flow shares one identity.
AppStore::BagOutput AppStore::fetch_bag(const std::string& guidArg) {
    std::string guid = guidArg.empty() ? get_guid() : guidArg;
    std::string url = std::string("https://") + PRIVATE_INIT_DOMAIN
                    + PRIVATE_INIT_PATH + "?guid=" + guid;
    HttpResponse res = m_http.get(url, {{"Accept", "application/xml"}});

    // Bag body is huge — log only status and size.
    if (m_debug)
        fprintf(stderr, "[DEBUG] bag status: %d (%zu bytes)\n",
                res.statusCode, res.body.size());

    if (res.statusCode != 200)
        throw IpaError("bag request failed: " + std::to_string(res.statusCode));

    PlistDict d = decode_plist(res.body);

    BagOutput out;

    // Extract redownloadProduct (simple flat lookup under urlBag)
    auto ubIt = d.find("urlBag");
    if (ubIt != d.end() && ubIt->second.isDict()) {
        out.redownloadEndpoint  = dict_str(ubIt->second.dictVal, "redownloadProduct");
        out.updateEndpoint      = dict_str(ubIt->second.dictVal, "updateProduct");
        out.volumeStoreDownloadEndpoint = dict_str(ubIt->second.dictVal, "volumeStoreDownloadProduct");
        out.songDownloadDoneEndpoint = dict_str(ubIt->second.dictVal, "songDownloadDone");
        m_updateEndpoint        = out.updateEndpoint;

        // ── SAP config fields (v2.4.0+) — must be extracted here, before
        //    the early returns below for the auth endpoint. ──────────────────
        const PlistDict& ub = ubIt->second.dictVal;
        out.signSapSetup     = dict_str(ub, "sign-sap-setup");
        out.signSapSetupCert = dict_str(ub, "sign-sap-setup-cert");
        std::string sapVer   = dict_str(ub, "sign-sap-version");
        if (!sapVer.empty()) {
            try { out.sapVersion = (uint32_t)std::stoul(sapVer); } catch (...) {}
        }
    }

    // Convert guid "AABBCCDDEEFF" → raw bytes for SapSigner::Config
    for (size_t i = 0; i + 1 < guid.size(); i += 2) {
        try { out.hardwareID.push_back((uint8_t)std::stoul(guid.substr(i,2),nullptr,16)); }
        catch (...) { break; }
    }

    // Extract authenticateAccount (complex: may need URL addend)
    std::string ep;

    // Try nested: d["urlBag"]["authenticateAccount"]
    if (ubIt != d.end() && ubIt->second.isDict()) {
        ep = dict_str(ubIt->second.dictVal, "authenticateAccount");
        if (!ep.empty()) goto FOUND_URL;
    }

    // Try flat: d["authenticateAccount"] directly
    {
        ep = dict_str(d, "authenticateAccount");
        if (!ep.empty()) goto FOUND_URL;
    }

    // Scan all top-level dict values for authenticateAccount
    for (auto& [k, v] : d) {
        if (v.isDict()) {
            ep = dict_str(v.dictVal, "authenticateAccount");
            if (!ep.empty()) goto FOUND_URL;
        }
    }

    FOUND_URL:
    if (!ep.empty()) {
        //Try to find URL addend by its path and add it to the tail
        std::string addend;
        std::string path = std::regex_replace(ep, std::regex(R"(^https?://[^/]+(/?))"), "");

        //Check if path is empty
        if (path.empty()) { out.authEndpoint = ep; return out; }

        // Temporary stack for linear deep XML traversal
        std::vector<std::reference_wrapper<const PlistDict>> xml_stack;
        xml_stack.push_back(d);

        while (!xml_stack.empty()) {
            const PlistDict& current_layer = xml_stack.back();
            xml_stack.pop_back();

            // Try to find the target path key on the current layer
            auto it = current_layer.find(path);
            if (it != current_layer.end()) {
                auto& v = it->second;

                // Check if it is a non-empty array
                if (v.isArray() && !v.arrayVal.empty()) {

                    // Get the first element from the array
                    auto& first_item = v.arrayVal[0];

                    // Check if it is a string and extract it
                    if (first_item.isString()) {
                        addend = first_item.strVal;
                        goto FOUND_ADDEND;
                    }
                }
            }

            // Push all nested dictionaries onto the stack for further processing
            for (auto& [k, v] : current_layer) {
                if (v.isDict()) {
                    xml_stack.push_back(v.dictVal);
                }
            }
        }
        FOUND_ADDEND:
        if (!addend.empty()) {
            if (ep.back() != '/') ep += "/";
            ep += addend;
        }

        ep += "/";
        out.authEndpoint = ep;
        return out;
    }

    // ── Extract SAP setup fields (v2.4.0+) ───────────────────────────────
    // Fallback to known-good hardcoded endpoint
    fprintf(stderr,
        "[WARN] Could not parse urlBag -- using default auth endpoint.\n"
        "       Retry with --debug to inspect the raw server response.\n");
    out.authEndpoint = "https://auth.itunes.apple.com/auth/v1/native/fast";
    return out;
}

// ── Login implementation ─────────────────────────────────────────────────

// ── Debug helpers for the SAP-signed authenticate request ────────────────
// The authenticate body carries the plain password (+ 2FA code); mask it so
// --debug output can be shared without leaking credentials.
static std::string mask_plist_password(const std::string& body) {
    static const std::string kKey = "<key>password</key>";
    std::string out = body;
    size_t k = out.find(kKey);
    if (k == std::string::npos) return out;
    size_t open  = out.find("<string>", k + kKey.size());
    size_t close = (open == std::string::npos) ? open : out.find("</string>", open);
    if (open == std::string::npos || close == std::string::npos) return out;
    open += 8; // strlen("<string>")
    out.replace(open, close - open, "********");
    return out;
}

static void debug_dump_auth_request(const std::string& url,
                                    const std::map<std::string, std::string>& headers,
                                    const std::string& body) {
    debug_dump_request("SAP-signed authenticate (password masked)", "POST",
                       url, headers, mask_plist_password(body));
}

static void debug_dump_auth_response(const HttpResponse& res) {
    // A 302 pod redirect echoes our request plist back in its body,
    // password included — mask the response the same way as the request.
    HttpResponse masked = res;
    masked.body = mask_plist_password(res.body);
    debug_dump_response("authenticate", masked);
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Private: login / purchase (implementation)
// ─────────────────────────────────────────────────────────────────────────────

Account AppStore::do_login(const std::string& email,
                 const std::string& password,
                 const std::string& authCode,
                 const std::string& guid,
                 const std::string& baseEndpoint,
                 SapSigner& signer)
{
    std::string  currentURL   = baseEndpoint;
    bool         retry        = true;
    bool         fromRedirect = false;  // pod-redirect sets attempt=1 (Go v2.4.0 behaviour)
    HttpResponse lastRes;
    PlistDict    lastData;

    for (int attempt = 1; retry && attempt <= 4; attempt++) {
        // Pod redirect: Apple expects attempt=1, not the outer loop counter
        int requestAttempt = fromRedirect ? 1 : attempt;
        fromRedirect = false;

        PlistDict payload;
        payload["appleId"]  = PlistValue::makeString(email);
        payload["attempt"]  = PlistValue::makeString(std::to_string(requestAttempt));
        payload["guid"]     = PlistValue::makeString(guid);
        payload["password"] = PlistValue::makeString(password + strip_spaces(authCode));
        payload["rmp"]      = PlistValue::makeString("0");
        payload["why"]      = PlistValue::makeString("signIn");

        std::string body = encode_plist_xml(payload);

        std::map<std::string, std::string> headers = {
            {"Content-Type", "application/x-www-form-urlencoded"},
            {"User-Agent",   CONFIGURATOR_UA},
        };

        // SAP-sign the request body (v2.4.0+)
        // Never send an unsigned attempt — it would only burn a sign-in try.
        try {
            auto sigBytes = signer.Sign(std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(body.data()), body.size()));
            headers[HTTP_HEADER_SAP_SIGNATURE] = SapBase64::Encode(sigBytes);
            if (m_debug)
                fprintf(stderr, "[DEBUG] SAP signature: %zu bytes\n", sigBytes.size());
        } catch (const std::exception& e) {
            throw IpaError(std::string("failed to sign login request: ") + e.what());
        }

        // Transport retry: up to 3 attempts on 204/404/5xx (250ms×attempt)
        // 429 → hard stop. Matches Go sendAuthenticationRequest behaviour.
        lastRes = {};
        for (int tx = 1; tx <= 3; ++tx) {
            if (m_debug) debug_dump_auth_request(currentURL, headers, body);
            lastRes = m_http.post(currentURL, body, headers);
            if (m_debug) debug_dump_auth_response(lastRes);
            int sc  = lastRes.statusCode;
            if (sc == 429)
                throw IpaError("rate limited by Apple (HTTP 429): " + lastRes.body);
            bool transient = (sc == 204 || sc == 404 || sc / 100 == 5);
            if (!transient) break;
            if (m_debug)
                fprintf(stderr, "[DEBUG] auth HTTP %d — transport retry %d/3\n", sc, tx);
            if (tx < 3)
                std::this_thread::sleep_for(std::chrono::milliseconds(tx * 250));
        }

        lastData = decode_plist(lastRes.body);

        std::string failureType     = dict_str(lastData, "failureType");
        std::string customerMessage = dict_str(lastData, "customerMessage");

        if (lastRes.statusCode == 302) {
            auto locIt = lastRes.headers.find("location");
            if (locIt == lastRes.headers.end())
                throw IpaError("redirect with no location header");
            currentURL   = locIt->second;
            fromRedirect = true;   // Apple expects attempt=1 on the pod-redirect POST
            retry = true;
        } else if (attempt == 1 && failureType == FAILURE_INVALID_CREDENTIALS) {
            retry = true;
        } else if (failureType.empty() && authCode.empty()
                   && customerMessage == CUSTOMER_MSG_BAD_LOGIN) {
            throw AuthCodeRequired();
        } else if (failureType.empty()
                   && customerMessage == CUSTOMER_MSG_ACCOUNT_DISABLED) {
            throw IpaError("account is disabled");
        } else if (!failureType.empty()) {
            throw IpaError(!customerMessage.empty() ? customerMessage : "something went wrong");
        } else if (lastRes.statusCode != 200
                   || dict_str(lastData, "passwordToken").empty()
                   || dict_str(lastData, "dsPersonId").empty()) {
            throw IpaError("something went wrong (status="
                           + std::to_string(lastRes.statusCode) + ")");
        } else {
            retry = false;
        }
    }

    if (retry) throw IpaError("too many login attempts");

    std::string sf, pod;
    {
        auto it = lastRes.headers.find(str_lower(HTTP_HEADER_STOREFRONT));
        if (it != lastRes.headers.end()) sf = it->second;
    }
    {
        auto it = lastRes.headers.find(str_lower(HTTP_HEADER_POD));
        if (it != lastRes.headers.end()) pod = it->second;
    }

    auto addrDict = dict_dict(dict_dict(lastData, "accountInfo"), "address");

    Account acc;
    acc.firstName           = dict_str(addrDict, "firstName");
    acc.lastName            = dict_str(addrDict, "lastName");
    acc.name                = acc.firstName + " " + acc.lastName;
    acc.email               = dict_str(dict_dict(lastData, "accountInfo"), "appleId");
    acc.passwordToken.set(  dict_str(lastData, "passwordToken"));
    acc.directoryServicesID = dict_str(lastData, "dsPersonId");
    acc.storeFront          = sf;
    acc.password.set(       password);
    acc.pod                 = pod;
    acc.fserial             = make_fserial(guid);  // fictitious device serial for volumeStoreDownload
    return acc;
}

// ── Purchase implementation ───────────────────────────────────────────────

PlistDict AppStore::do_purchase(const Account& acc, const App& app,
                     const std::string& guid, const std::string& pricingParam)
{
    std::string pod_prefix;
    if (!acc.pod.empty()) pod_prefix = "p" + acc.pod + "-";

    std::string url = "https://" + pod_prefix + std::string(PRIVATE_AS_DOMAIN)
                    + PRIVATE_AS_PATH_PURCHASE;

    PlistDict payload;
    payload["appExtVrsId"]               = PlistValue::makeString("0");
    payload["hasAskedToFulfillPreorder"] = PlistValue::makeString("true");
    payload["buyWithoutAuthorization"]   = PlistValue::makeString("true");
    payload["hasDoneAgeCheck"]           = PlistValue::makeString("true");
    payload["guid"]                      = PlistValue::makeString(guid);
    payload["needDiv"]                   = PlistValue::makeString("0");
    payload["origPage"]                  = PlistValue::makeString("Software-" + std::to_string(app.id));
    payload["origPageLocation"]          = PlistValue::makeString("Buy");
    payload["price"]                     = PlistValue::makeString("0");
    payload["pricingParameters"]         = PlistValue::makeString(pricingParam);
    payload["productType"]               = PlistValue::makeString("C");
    payload["salableAdamId"]             = PlistValue::makeInt(app.id);

    std::map<std::string, std::string> headers = {
        {"Content-Type",        "application/x-apple-plist"},
        {"iCloud-DSID",         acc.directoryServicesID},
        {"X-Dsid",              acc.directoryServicesID},
        {"X-Apple-Store-Front", acc.storeFront},
        {"X-Token",             acc.passwordToken.get()},
    };

    std::string body = encode_plist_xml(payload);
    if (m_debug) debug_dump_request("buyProduct", "POST", url, headers, body);
    HttpResponse res  = m_http.post(url, body, headers);
    if (m_debug) debug_dump_response("buyProduct", res);
    PlistDict    data  = decode_plist(res.body);

    std::string failureType     = dict_str(data, "failureType");
    std::string customerMessage = dict_str(data, "customerMessage");
    std::string jingleDocType   = dict_str(data, "jingleDocType");
    int64_t     status          = dict_int(data, "status");

    if (failureType == FAILURE_TEMPORARILY_UNAVAILABLE)   throw IpaError("item is temporarily unavailable");
    if (failureType == FAILURE_ALREADY_PURCHASED)         throw IpaError("license already exists");
    if (customerMessage == CUSTOMER_MSG_SUBSCRIPTION_REQ) throw SubscriptionRequired();
    if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED)    throw PasswordTokenExpired();
    if (customerMessage == CUSTOMER_MSG_SIGN_IN)          throw PasswordTokenExpired();
    if (!failureType.empty() && !customerMessage.empty()) throw IpaError(customerMessage);
    if (!failureType.empty())                             throw IpaError("something went wrong");
    if (res.statusCode == 500)                            throw IpaError("license already exists");
    if (jingleDocType != "purchaseSuccess" || status != 0)
        throw IpaError("failed to purchase app");

    // Return full result — caller can use songList if present (paid apps)
    return data;
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Private: IPA patching
// ─────────────────────────────────────────────────────────────────────────────

// ── ZIP patching ──────────────────────────────────────────────────────────
// Injects a patched iTunesMetadata.plist into the downloaded IPA.
// Uses minizip when available; falls back to a pure C++ copy without patching.

void AppStore::apply_patches(const PlistDict& item,
                   const Account&   acc,
                   const std::string& srcPath,
                   const std::string& dstPath,
                   const std::vector<Sinf>& sinfs)
{
#ifdef HAVE_MINIZIP
    auto metaIt = item.find("metadata");
    PlistDict metadata;
    if (metaIt != item.end() && metaIt->second.isDict())
        metadata = metaIt->second.dictVal;

    // Add account identity fields
    metadata["appleId"]  = PlistValue::makeString(acc.email);
    metadata["userName"] = PlistValue::makeString(acc.name);

    // purchaseDate — current download time (iTunes uses download time, not purchase time)
    time_t now = std::time(nullptr);
    std::string purchaseDateStr;
    {
        struct tm t;
#ifdef _WIN32
        gmtime_s(&t, &now);
#else
        gmtime_r(&now, &t);
#endif
        char buf[64];
        snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                 t.tm_year+1900, t.tm_mon+1, t.tm_mday,
                 t.tm_hour, t.tm_min, t.tm_sec);
        purchaseDateStr = buf;
    }

    // Construct com.apple.iTunesStore.downloadInfo — mirrors what iTunes writes
    {
        PlistDict accountInfo;
        accountInfo["AppleID"]          = PlistValue::makeString(acc.email);
        accountInfo["UserName"]         = PlistValue::makeString(acc.name);
        accountInfo["AccountStoreFront"]= PlistValue::makeString(acc.storeFront);
        accountInfo["DSPersonID"]       = PlistValue::makeInt(
                                            std::stoll(acc.directoryServicesID.empty() ? "0" : acc.directoryServicesID));
        accountInfo["PurchaserID"]      = PlistValue::makeInt(
                                            std::stoll(acc.directoryServicesID.empty() ? "0" : acc.directoryServicesID));
        accountInfo["DownloaderID"]     = PlistValue::makeInt(0);
        accountInfo["FamilyID"]         = PlistValue::makeInt(0);
        accountInfo["FirstName"]        = PlistValue::makeString(acc.firstName);
        accountInfo["LastName"]         = PlistValue::makeString(acc.lastName);

        PlistDict downloadInfo;
        downloadInfo["accountInfo"]  = PlistValue::makeDict(accountInfo);
        downloadInfo["purchaseDate"] = PlistValue::makeString(purchaseDateStr);

        metadata["com.apple.iTunesStore.downloadInfo"] = PlistValue::makeDict(downloadInfo);
    }

    // is-purchased-redownload: true (always set by iTunes for purchased apps)
    metadata["is-purchased-redownload"] = PlistValue::makeBool(true);
    metadata["purchaseDate"] = PlistValue::makeDate(purchaseDateStr);

    // storeCohort — constructed by iTunes using current time + storefront number
    {
        // Extract numeric storefront ID (e.g. "143441-16,32" → "143441")
        std::string sf = acc.storeFront;
        size_t dash = sf.find('-');
        if (dash != std::string::npos) sf = sf.substr(0, dash);
        // Current time in milliseconds
        int64_t ms = (int64_t)now * 1000LL;
        char cohort[256];
        snprintf(cohort, sizeof(cohort),
                 "10|date=%lld&sf=%s&app=com.apple.iTunes&pgtp=Purchases&prpg=Purchases",
                 (long long)ms, sf.c_str());
        metadata["storeCohort"] = PlistValue::makeString(cohort);
    }

    std::string metaStr  = encode_plist_xml(metadata);
    std::vector<uint8_t> metaBytes(metaStr.begin(), metaStr.end());

    // Download iTunesArtwork
    std::vector<uint8_t> artworkBytes;
    try {
        std::string artworkURL = dict_str(item, "artworkURL");
        if (!artworkURL.empty()) {
            HttpResponse artRes = m_http.get(artworkURL);
            if (artRes.statusCode == 200 && !artRes.body.empty())
                artworkBytes.assign(artRes.body.begin(), artRes.body.end());
        }
    }
    catch (const std::exception& e) {
        fprintf(stderr, "[WARN] Artwork Download Failed: %s\n", e.what());
    }

    patch_with_minizip(srcPath, dstPath, metaBytes, artworkBytes, sinfs);
#else
    std::error_code ec;
    fs::copy_file(ipt::fs_path(srcPath), ipt::fs_path(dstPath),
                  fs::copy_options::overwrite_existing, ec);
    if (ec) throw IpaError("failed to copy IPA: " + ec.message());
#endif
}

#ifdef HAVE_MINIZIP
void AppStore::patch_with_minizip(const std::string& srcPath,
                               const std::string& dstPath,
                               const std::vector<uint8_t>& metaBytes,
                               const std::vector<uint8_t>& artworkBytes,
                               const std::vector<Sinf>& sinfs)
{
    // ── Step 1: raw-copy the original IPA → destination ──────────────────
    {
        std::ifstream in(ipt::fs_path(srcPath),  std::ios::binary);
        std::ofstream out(ipt::fs_path(dstPath), std::ios::binary | std::ios::trunc);
        if (!in)  throw IpaError("minizip: cannot open source IPA");
        if (!out) throw IpaError("minizip: cannot create output IPA");
        out << in.rdbuf();
    }

    // ── Step 2: collect bundle info needed for sinf path ─────────────────
    std::string bundleName;
    std::string bundleExecutable;
    std::vector<std::string> sinfPaths;

    if (!sinfs.empty()) {
        unzFile probe = ipt_unzOpen(srcPath);
        if (!probe) throw IpaError("minizip: cannot open source for probe");
        int rc = unzGoToFirstFile(probe);
        while (rc == UNZ_OK) {
            char name[1024] = {};
            unz_file_info fi;
            unzGetCurrentFileInfo(probe, &fi, name, sizeof(name),
                                  nullptr, 0, nullptr, 0);
            std::string n(name);

            if (bundleName.empty()
                && n.find(".app/Info.plist") != std::string::npos
                && n.find("/Watch/") == std::string::npos)
            {
                size_t appPos   = n.rfind(".app/Info.plist");
                size_t slashPos = n.rfind('/', appPos - 1);
                bundleName = n.substr(slashPos + 1, appPos - slashPos - 1);
            }

            if (bundleExecutable.empty()
                && n.find(".app/Info.plist") != std::string::npos
                && n.find("/Watch/") == std::string::npos)
            {
                unzOpenCurrentFile(probe);
                std::vector<uint8_t> buf(fi.uncompressed_size);
                unzReadCurrentFile(probe, buf.data(), (unsigned)buf.size());
                unzCloseCurrentFile(probe);
                bundleExecutable = extract_plist_string(buf, "CFBundleExecutable");
            }

            if (sinfPaths.empty()
                && n.find(".app/SC_Info/Manifest.plist") != std::string::npos)
            {
                unzOpenCurrentFile(probe);
                std::vector<uint8_t> buf(fi.uncompressed_size);
                unzReadCurrentFile(probe, buf.data(), (unsigned)buf.size());
                unzCloseCurrentFile(probe);
                sinfPaths = extract_sinf_paths(buf);
            }

            rc = unzGoToNextFile(probe);
        }
        unzClose(probe);
    }

    // ── Step 3: open the copy in append mode and inject new files ─────────
    zipFile dst = ipt_zipOpen(dstPath, APPEND_STATUS_ADDINZIP);
    if (!dst) throw IpaError("minizip: failed to open output IPA for append");

    // iTunes order: iTunesMetadata.plist first, sinf(s), iTunesArtwork last
    auto append_file = [&](const char* path,
                            const void* data, unsigned size,
                            int method)
    {
        zip_fileinfo zfi = {};
        zipOpenNewFileInZip(dst, path, &zfi,
            nullptr, 0, nullptr, 0, nullptr,
            method, method == 0 ? 0 : Z_DEFAULT_COMPRESSION);
        zipWriteInFileInZip(dst, data, size);
        zipCloseFileInZip(dst);
    };

    append_file("iTunesMetadata.plist",
                metaBytes.data(), (unsigned)metaBytes.size(),
                Z_DEFLATED);

    if (!sinfs.empty() && !bundleName.empty()) {
        if (!sinfPaths.empty()) {
            size_t count = std::min(sinfs.size(), sinfPaths.size());
            for (size_t i = 0; i < count; i++) {
                std::string sp = "Payload/" + bundleName + ".app/" + sinfPaths[i];
                append_file(sp.c_str(),
                            sinfs[i].data.data(), (unsigned)sinfs[i].data.size(),
                            Z_DEFLATED);
            }
        } else if (!bundleExecutable.empty()) {
            std::string sp = "Payload/" + bundleName + ".app/SC_Info/"
                           + bundleExecutable + ".sinf";
            append_file(sp.c_str(),
                        sinfs[0].data.data(), (unsigned)sinfs[0].data.size(),
                        Z_DEFLATED);
        }
    }

    if (!artworkBytes.empty())
        append_file("iTunesArtwork",
                    artworkBytes.data(), (unsigned)artworkBytes.size(),
                    Z_DEFLATED);

    zipClose(dst, nullptr);
}

// Extract a string value from a binary or XML plist by key name.
// Used to read CFBundleExecutable from Info.plist without a full plist parser.
std::string AppStore::extract_plist_string(const std::vector<uint8_t>& data,
                                         const std::string& key)
{
    // Try XML first
    std::string s(data.begin(), data.end());
    size_t kpos = s.find("<key>" + key + "</key>");
    if (kpos != std::string::npos) {
        size_t vs = s.find("<string>", kpos);
        size_t ve = s.find("</string>", vs);
        if (vs != std::string::npos && ve != std::string::npos)
            return s.substr(vs + 8, ve - vs - 8);
    }
    // Binary plist: key is preceded by its length byte, value follows similarly.
    // Simple scan: find the key bytes and read the next string atom.
    // Sufficient for short ASCII values like CFBundleExecutable.
    for (size_t i = 0; i + key.size() < data.size(); i++) {
        if (memcmp(data.data() + i, key.data(), key.size()) == 0) {
            // Found key string; next string atom in binary plist follows
            // after a string marker byte (0x5N where N=length, or 0x6N for UTF-16)
            size_t j = i + key.size();
            while (j < data.size()) {
                uint8_t b = data[j++];
                if ((b & 0xF0) == 0x50) { // ASCII string, length = b & 0x0F
                    int len = b & 0x0F;
                    if (j + len <= data.size())
                        return std::string((char*)data.data() + j, len);
                }
            }
        }
    }
    return "";
}

// Parse SinfPaths array from SC_Info/Manifest.plist (XML or binary plist)
std::vector<std::string> AppStore::extract_sinf_paths(const std::vector<uint8_t>& data)
{
    std::vector<std::string> paths;
    std::string s(data.begin(), data.end());
    // XML plist path
    size_t kpos = s.find("<key>SinfPaths</key>");
    if (kpos != std::string::npos) {
        size_t astart = s.find("<array>", kpos);
        size_t aend   = s.find("</array>", astart);
        if (astart != std::string::npos && aend != std::string::npos) {
            std::string arr = s.substr(astart + 7, aend - astart - 7);
            size_t pos = 0;
            while (true) {
                size_t vs = arr.find("<string>", pos);
                size_t ve = arr.find("</string>", vs);
                if (vs == std::string::npos || ve == std::string::npos) break;
                paths.push_back(arr.substr(vs + 8, ve - vs - 8));
                pos = ve + 9;
            }
        }
        return paths;
    }
    // Binary plist: scan for "SinfPaths" key then collect following string atoms
    const std::string marker = "SinfPaths";
    size_t mpos = s.find(marker);
    if (mpos != std::string::npos) {
        size_t j = mpos + marker.size();
        // Skip array marker
        while (j < data.size() && (data[j] & 0xF0) != 0x50 && (data[j] & 0xF0) != 0xA0) j++;
        if (j < data.size() && (data[j] & 0xF0) == 0xA0) {
            int count = data[j] & 0x0F;
            j++;
            for (int i = 0; i < count && j < data.size(); i++) {
                uint8_t b = data[j++];
                if ((b & 0xF0) == 0x50) {
                    int len = b & 0x0F;
                    if (j + len <= data.size()) {
                        paths.push_back(std::string((char*)data.data() + j, len));
                        j += len;
                    }
                }
            }
        }
    }
    return paths;
}
#endif

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Private: URL / path / string helpers
// ─────────────────────────────────────────────────────────────────────────────

// ── URL builders ─────────────────────────────────────────────────────────

std::string AppStore::search_url(const std::string& term,
                               const std::string& cc, int limit)
{
    std::map<std::string, std::string> p = {
        {"entity",  "software,iPadSoftware"},
        {"limit",   std::to_string(limit)},
        {"media",   "software"},
        {"term",    term},
        {"country", cc},
    };
    return std::string("https://") + ITUNES_API_DOMAIN
         + ITUNES_API_PATH_SEARCH + "?" + build_query(p);
}

std::string AppStore::lookup_url(const std::string& bundleID,
                               const std::string& cc)
{
    std::map<std::string, std::string> p = {
        {"entity",   "software,iPadSoftware"},
        {"limit",    "1"},
        {"media",    "software"},
        {"bundleId", bundleID},
        {"country",  cc},
    };
    return std::string("https://") + ITUNES_API_DOMAIN
         + ITUNES_API_PATH_LOOKUP + "?" + build_query(p);
}

// ── Path helpers (C++17 std::filesystem — no POSIX needed) ───────────────

std::string AppStore::resolve_destination(const App& app,
                                       const std::string& version,
                                       const std::string& outputPath,
                                       const std::string& displayName,
                                       const std::string& ext)
{
    std::string fname = make_filename(app, version, displayName, ext);
    if (outputPath.empty()) {
        return ipt::to_utf8(fs::current_path() / fname);
    }
    // Keep the user's UTF-8 path intact: fs::path::string() returns the active
    // ANSI code page on Windows, so join as plain UTF-8 instead of round-tripping.
    if (fs::is_directory(ipt::fs_path(outputPath))) {
        char last = outputPath.empty() ? '\0' : outputPath.back();
        std::string sep = (last == '/' || last == '\\') ? "" : "/";
        return outputPath + sep + fname;
    }
    return outputPath;
}

std::string AppStore::make_filename(const App& app, const std::string& version,
                                    const std::string& displayName,
                                    const std::string& ext) {
    return build_base_filename(displayName, app, version) + ext;
}

int64_t AppStore::file_size(const std::string& path) {
    std::error_code ec;
    auto sz = fs::file_size(ipt::fs_path(path), ec);
    return ec ? 0 : (int64_t)sz;
}

// ── String helpers ────────────────────────────────────────────────────────

std::string AppStore::strip_spaces(const std::string& s) {
    std::string out;
    for (char c : s) if (c != ' ') out += c;
    return out;
}

std::string AppStore::str_lower(const char* s) {
    std::string out(s);
    for (char& c : out) c = (char)tolower((unsigned char)c);
    return out;
}

