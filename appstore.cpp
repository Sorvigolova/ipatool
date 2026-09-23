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
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "ws2_32.lib")
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
#endif

namespace fs = std::filesystem;

#include "sap_resources.h"
#include "sap_embedded_assets.h"

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
    std::ostringstream out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c=='-' || c=='_' || c=='.' || c=='~') {
            out << c;
        } else {
            out << '%' << std::uppercase << std::hex << (int)c;
        }
    }
    return out.str();
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

// Same failure mapping as the top of download()/list_versions().
static void throw_on_store_failure(const PlistDict& data) {
    std::string failureType     = dict_str(data, "failureType");
    std::string customerMessage = dict_str(data, "customerMessage");
    if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED ||
        failureType == FAILURE_SIGN_IN_REQUIRED        ||
        failureType == FAILURE_DEVICE_VERIFICATION)
        throw PasswordTokenExpired();
    if (customerMessage == CUSTOMER_MSG_SIGN_IN)   throw PasswordTokenExpired();
    if (failureType == FAILURE_LICENSE_NOT_FOUND)  throw LicenseRequired();
    if (!failureType.empty() && !customerMessage.empty())
        throw IpaError("received error: " + customerMessage);
    if (!failureType.empty())
        throw IpaError("received error: " + failureType);
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Bag / Login
// ─────────────────────────────────────────────────────────────────────────────

AppStore::BagOutput AppStore::fetch_bag() {
    return fetch_bag_impl(get_guid());
}

Account AppStore::login(const std::string& email,
              const std::string& password,
              const std::string& authCode,
              const std::string& endpoint)
{
    std::string guid = get_guid();

    // Fetch bag for both the auth endpoint and SAP config
    BagOutput bag = fetch_bag_impl(guid);
    std::string loginEndpoint = endpoint.empty() ? bag.authEndpoint : endpoint;

    // Create SAP signer — performs handshake with Apple servers (v2.4.0+)
    std::unique_ptr<SapSigner> signer;
    if (!bag.signSapSetup.empty() && !bag.signSapSetupCert.empty()
        && bag.sapVersion == 200 && !bag.hardwareID.empty())
    {
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
            if (m_debug) fprintf(stderr, "[DEBUG] SAP signer initialized OK\n");
        } catch (const std::exception& e) {
            if (m_debug)
                fprintf(stderr, "[DEBUG] SAP signer init failed: %s\n", e.what());
            // Non-fatal: try unsigned (Apple may reject, but let it fail at the server)
            signer.reset();
        }
    } else if (m_debug) {
        fprintf(stderr, "[DEBUG] SAP config missing from bag — login will be unsigned\n");
    }

    Account acc = do_login(email, password, authCode, guid, loginEndpoint, signer.get());
    return acc;
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Search / Lookup
// ─────────────────────────────────────────────────────────────────────────────

AppStore::SearchOutput AppStore::search(const Account& acc, const std::string& term, int limit) {
    std::string cc  = country_code_from_storefront(acc.storeFront);
    std::string url = search_url(term, cc, limit);

    HttpResponse res = m_http.get(url);
    if (res.statusCode != 200)
        throw IpaError("search request failed: " + std::to_string(res.statusCode));

    auto sr = parse_search_json(res.body);
    return {sr.count, sr.results};
}

App AppStore::lookup(const Account& acc, const std::string& bundleID) {
    std::string cc  = country_code_from_storefront(acc.storeFront);
    std::string url = lookup_url(bundleID, cc);

    HttpResponse res = m_http.get(url);
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

    HttpResponse res = m_http.get(url);
    if (res.statusCode != 200)
        throw IpaError("lookup request failed: " + std::to_string(res.statusCode));

    auto sr = parse_search_json(res.body);
    if (sr.results.empty()) throw IpaError("app not found");
    return sr.results[0];
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
                        const std::string& redownloadEndpoint)
{
    std::string guid = get_guid();

    if (m_debug) {
        std::string pod_pfx;
        if (!acc.pod.empty()) pod_pfx = "p" + acc.pod + "-";
        std::string dbgUrl = "https://" + pod_pfx + std::string(PRIVATE_AS_DOMAIN)
                           + PRIVATE_AS_PATH_DOWNLOAD + "?guid=" + guid;
        fprintf(stderr, "[DEBUG] download URL: %s\n", dbgUrl.c_str());
        fprintf(stderr, "[DEBUG] dsid: %s\n", acc.directoryServicesID.c_str());
        fprintf(stderr, "[DEBUG] storefront: '%s'\n", acc.storeFront.c_str());
        fprintf(stderr, "[DEBUG] passwordToken length: %zu\n", acc.passwordToken.get().size());
        fprintf(stderr, "[DEBUG] pod: '%s'\n", acc.pod.c_str());
    }

    PlistDict data = send_download_product(acc, app, guid, externalVersionID, redownloadEndpoint);

    std::string failureType     = dict_str(data, "failureType");
    std::string customerMessage = dict_str(data, "customerMessage");

    if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED ||
        failureType == FAILURE_SIGN_IN_REQUIRED        ||   // "2042" — v2.4.0
        failureType == FAILURE_DEVICE_VERIFICATION)         // "1008" — v2.4.0
        throw PasswordTokenExpired();
    if (customerMessage == CUSTOMER_MSG_SIGN_IN)        throw PasswordTokenExpired();
    if (failureType == FAILURE_LICENSE_NOT_FOUND)      throw LicenseRequired();
    if (!failureType.empty() && !customerMessage.empty())
        throw IpaError("received error: " + customerMessage);
    if (!failureType.empty())
        throw IpaError("received error: " + failureType);

    auto songList = dict_arr(data, "songList");
    if (songList.empty()) {
        if (!customerMessage.empty()) throw IpaError(customerMessage);

        // purchaseSuccess + empty songList — try redownload endpoint before giving up.
        // Apple sometimes serves previously purchased (or just-purchased) apps through
        // the redownload path even when volumeStore returns empty songList.
        std::string jingle = dict_str(data, "jingleDocType");
        if ((jingle == "purchaseSuccess" || jingle.empty()) && !redownloadEndpoint.empty()) {
            if (m_debug)
                fprintf(stderr, "[DEBUG] empty songList after purchase — trying redownload endpoint\n");
            PlistDict rdData = redownload_product(acc, app, guid, redownloadEndpoint,
                                                  externalVersionID, /*isMac=*/false,
                                                  "redownload");
            auto rdList = dict_arr(rdData, "songList");
            if (!rdList.empty()) {
                data     = std::move(rdData);
                songList = std::move(rdList);
                goto process_songlist;
            }
            throw_on_store_failure(rdData);
        }

        if (jingle == "purchaseSuccess")
            throw IpaError("app is not available for download in your region/storefront"
                           " (license was granted but download was blocked)");
        throw IpaError("invalid response: empty songList");
    }
    process_songlist:

    auto& itemVal = songList[0];
    if (!itemVal.isDict()) throw IpaError("invalid response: bad songList item");

    const PlistDict& item       = itemVal.dictVal;
    std::string      downloadURL = dict_str(item, "URL");
    std::string      version     = "unknown";

    auto metaIt  = item.find("metadata");
    PlistDict metadata;
    if (metaIt != item.end() && metaIt->second.isDict()) {
        metadata = metaIt->second.dictVal;
        auto vIt = metadata.find("bundleShortVersionString");
        if (vIt != metadata.end() && vIt->second.isString())
            version = vIt->second.str();
    }

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

        // Resolve output path with .pkg extension
        std::string pkgDest = outputPath;
        if (pkgDest.empty() || fs::is_directory(pkgDest)) {
            std::string fname = app.name + "_" + std::to_string(app.id) + "_" + version + ".pkg";
            // sanitize filename
            for (char& c : fname) if (c=='/' || c=='\\' || c==':') c='_';
            pkgDest = pkgDest.empty() ? fname : (pkgDest + "/" + fname);
        } else if (pkgDest.size() < 4 || pkgDest.substr(pkgDest.size()-4) != ".pkg") {
            pkgDest += ".pkg";
        }

        std::string tmpPkg = pkgDest + ".tmp";
        int64_t rangeStart = file_size(tmpPkg);
        m_http.download(downloadURL, tmpPkg, rangeStart, progress);

        if (dpInfo.empty()) {
            // Unencrypted (drmVersionNumber=0) — rename directly
            if (m_debug) fprintf(stderr, "[DEBUG] macOS pkg is unencrypted, saving directly\n");
            std::error_code ec;
            fs::rename(tmpPkg, pkgDest, ec);
            if (ec) {
                fs::copy_file(tmpPkg, pkgDest,
                              fs::copy_options::overwrite_existing, ec);
                fs::remove(tmpPkg, ec);
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
                std::ifstream src_f(tmpPkg, std::ios::binary);
                std::ofstream dst_f(decTmp, std::ios::binary | std::ios::trunc);
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
            fs::remove(tmpPkg);
            std::error_code ec;
            fs::rename(decTmp, pkgDest, ec);
            if (ec) { fs::copy_file(decTmp, pkgDest, fs::copy_options::overwrite_existing); fs::remove(decTmp); }
        }
        return { pkgDest, sinfs };
    }

    // ── iOS IPA path ────────────────────────────────────────────────────────
    std::string dest    = resolve_destination(app, version, outputPath);
    std::string tmpDest = dest + ".tmp";

    int64_t rangeStart = file_size(tmpDest);
    m_http.download(downloadURL, tmpDest, rangeStart, progress);

    apply_patches(item, acc, tmpDest, dest, sinfs);
    fs::remove(tmpDest);

    return {dest, sinfs};
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — List Versions / Get Version Metadata
// ─────────────────────────────────────────────────────────────────────────────

AppStore::ListVersionsOutput AppStore::list_versions(const Account& acc, const App& app,
                                 const std::string& redownloadEndpoint) {
    std::string guid = get_guid();

    PlistDict data = send_download_product(acc, app, guid, "", redownloadEndpoint);

    std::string failureType     = dict_str(data, "failureType");
    std::string customerMessage = dict_str(data, "customerMessage");
    if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED ||
        failureType == FAILURE_SIGN_IN_REQUIRED        ||   // "2042" — v2.4.0
        failureType == FAILURE_DEVICE_VERIFICATION)         // "1008" — v2.4.0
        throw PasswordTokenExpired();
    if (customerMessage == CUSTOMER_MSG_SIGN_IN)        throw PasswordTokenExpired();
    if (failureType == FAILURE_LICENSE_NOT_FOUND)      throw LicenseRequired();
    if (!failureType.empty() && !customerMessage.empty())
        throw IpaError("received error: " + customerMessage);
    if (!failureType.empty())
        throw IpaError("received error: " + failureType);

    auto songList = dict_arr(data, "songList");
    if (songList.empty()) {
        if (!customerMessage.empty()) throw IpaError(customerMessage);

        // Empty songList on list_versions — try redownload endpoint before giving up.
        // Some apps (e.g. removed from local storefront) return songList via redownload
        // even when volumeStore returns empty. Matches behaviour of download flow.
        std::string jingle = dict_str(data, "jingleDocType");
        if (!redownloadEndpoint.empty()) {
            if (m_debug)
                fprintf(stderr, "[DEBUG] list_versions: empty songList — trying redownload endpoint\n");
            PlistDict rdData = redownload_product(acc, app, guid, redownloadEndpoint,
                                                  "", /*isMac=*/false,
                                                  "list_versions redownload");
            auto rdList = dict_arr(rdData, "songList");
            if (!rdList.empty()) {
                data     = std::move(rdData);
                songList = std::move(rdList);
                goto lv_process_songlist;
            }
            throw_on_store_failure(rdData);
        }

        if (jingle == "purchaseSuccess")
            throw IpaError("app is not available for download in your region/storefront"
                           " (license was granted but download was blocked)");
        throw IpaError("invalid response: empty songList");
    }
    lv_process_songlist:
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
    } // lv_process_songlist block
}

AppStore::GetVersionMetadataOutput AppStore::get_version_metadata(const Account& acc,
                                               const App& app,
                                               const std::string& versionID,
                                               const std::string& redownloadEndpoint) {
    std::string guid = get_guid();

    PlistDict data = send_download_product(acc, app, guid, versionID, redownloadEndpoint);

    std::string failureType     = dict_str(data, "failureType");
    std::string customerMessage = dict_str(data, "customerMessage");
    if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED ||
        failureType == FAILURE_SIGN_IN_REQUIRED        ||   // "2042" — v2.4.0
        failureType == FAILURE_DEVICE_VERIFICATION)         // "1008" — v2.4.0
        throw PasswordTokenExpired();
    if (customerMessage == CUSTOMER_MSG_SIGN_IN)        throw PasswordTokenExpired();
    if (failureType == FAILURE_LICENSE_NOT_FOUND)      throw LicenseRequired();
    if (!failureType.empty() && !customerMessage.empty())
        throw IpaError("received error: " + customerMessage);
    if (!failureType.empty())
        throw IpaError("received error: " + failureType);

    auto songList = dict_arr(data, "songList");
    if (songList.empty()) {
        if (!customerMessage.empty()) throw IpaError(customerMessage);
        // purchaseSuccess + empty songList = app not available in this storefront/region
        // (e.g. VPN apps removed from Russian App Store by government order)
        std::string jingle = dict_str(data, "jingleDocType");
        if (jingle == "purchaseSuccess")
            throw IpaError("app is not available for download in your region/storefront"
                           " (license was granted but download was blocked)");
        throw IpaError("invalid response: empty songList");
    }
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
// AppStore — private helpers
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

// ── sendDownloadProduct — shared volumeStore->redownload helper ─────────
PlistDict AppStore::send_download_product(const Account& acc, const App& app,
                                 const std::string& guid,
                                 const std::string& externalVersionID,
                                 const std::string& redownloadEndpoint,
                                 bool isMac)
{
    std::string pod_prefix;
    if (!acc.pod.empty()) pod_prefix = "p" + acc.pod + "-";
    std::string vsUrl = "https://" + pod_prefix + std::string(PRIVATE_AS_DOMAIN)
                      + PRIVATE_AS_PATH_DOWNLOAD + "?guid=" + guid;

    std::map<std::string, std::string> hdrs = {
        {"Content-Type",         "application/x-apple-plist"},
        {"iCloud-DSID",          acc.directoryServicesID},
        {"X-Dsid",               acc.directoryServicesID},
        {"X-Apple-Store-Front",  acc.storeFront},
        {"X-Token",              acc.passwordToken.get()},
    };

    // volumeStore payload: version pin key = externalVersionId
    auto make_vs_payload = [&]() {
        PlistDict p;
        p["creditDisplay"] = PlistValue::makeString("");
        p["guid"]          = PlistValue::makeString(guid);
        p["salableAdamId"] = PlistValue::makeInt(app.id);
        p["serialNumber"]  = PlistValue::makeString("0");  // PR #500 fix (v2.4.0)
        if (!externalVersionID.empty())
            p["externalVersionId"] = PlistValue::makeString(externalVersionID);
        return p;
    };

    // 1. Try volumeStore (primary — every app that works today keeps using this)
    HttpResponse vsRes = m_http.post(vsUrl, encode_plist_xml(make_vs_payload()), hdrs);
    if (m_debug) {
        fprintf(stderr, "[DEBUG] volumeStore status: %d\n", vsRes.statusCode);
        fprintf(stderr, "[DEBUG] volumeStore body:\n%s\n", vsRes.body.c_str());
    }
    PlistDict data        = decode_plist(vsRes.body);
    std::string failureType    = dict_str(data, "failureType");
    std::string customerMsg    = dict_str(data, "customerMessage");
    // Also check metrics.messageCode (Apple wraps 2042 there in AuthTokenResumeFreeBuy)
    if (failureType.empty()) {
        auto metricsIt = data.find("metrics");
        if (metricsIt != data.end() && metricsIt->second.isDict())
            failureType = dict_str(metricsIt->second.dictVal, "messageCode");
    }
    if (m_debug && !failureType.empty())
        fprintf(stderr, "[DEBUG] volumeStore failureType: '%s' customerMsg: '%s'\n",
                failureType.c_str(), customerMsg.c_str());

    // 2a. On 2042 AuthTokenResumeFreeBuy — Apple wants user to "confirm" the download.
    //     Retry with hasBeenAuthedForBuy=true (equivalent of clicking "Download" in the dialog).
    //     Do NOT re-authenticate — the token is fine, Apple just needs this flag.
    if (failureType == FAILURE_SIGN_IN_REQUIRED) {
        auto dialogIt = data.find("dialog");
        bool isAuthDialog = (dialogIt != data.end() && dialogIt->second.isDict() &&
                             dict_str(dialogIt->second.dictVal, "kind") == "authorization");
        if (isAuthDialog) {
            auto auth_payload = make_vs_payload();
            auth_payload["hasBeenAuthedForBuy"] = PlistValue::makeString("true");
            HttpResponse authRes = m_http.post(vsUrl, encode_plist_xml(auth_payload), hdrs);
            if (m_debug) {
                fprintf(stderr, "[DEBUG] hasBeenAuthedForBuy retry status: %d\n", authRes.statusCode);
                fprintf(stderr, "[DEBUG] hasBeenAuthedForBuy retry body:\n%s\n", authRes.body.c_str());
            }
            data        = decode_plist(authRes.body);
            failureType = dict_str(data, "failureType");
            if (failureType.empty()) {
                auto mit = data.find("metrics");
                if (mit != data.end() && mit->second.isDict())
                    failureType = dict_str(mit->second.dictVal, "messageCode");
            }
            if (m_debug && !failureType.empty())
                fprintf(stderr, "[DEBUG] after hasBeenAuthedForBuy failureType: '%s'\n", failureType.c_str());
        }
    }

    // 2b. On 5002 (licensed app — e.g. Teams) fall back to redownloadProduct
    if (failureType == FAILURE_ALREADY_PURCHASED && !redownloadEndpoint.empty()) {
        PlistDict rdData = redownload_product(acc, app, guid, redownloadEndpoint,
                                              externalVersionID, isMac,
                                              "redownload fallback (5002)");
        auto      rdSongList     = dict_arr(rdData, "songList");
        std::string rdCustomerMsg = dict_str(rdData, "customerMessage");

        // If redownload can't serve the app (empty songList — for any reason:
        //   "No Longer Available"               → transient 5002, app not in library
        //   "Redownload Unavailable with This Apple Account" → no license yet
        //   any other refusal
        // ) → retry volumeStore.
        // The retry surfaces the real Apple error (e.g. 9610 → LicenseRequired
        // so --purchase can kick in, or a clean success if the 5002 was transient).
        if (rdSongList.empty()) {
            if (m_debug)
                fprintf(stderr,
                    "[DEBUG] redownload empty (msg: '%s') — retrying volumeStore\n",
                    rdCustomerMsg.c_str());
            HttpResponse retryRes = m_http.post(vsUrl, encode_plist_xml(make_vs_payload()), hdrs);
            if (m_debug) {
                fprintf(stderr, "[DEBUG] volumeStore retry status: %d\n", retryRes.statusCode);
                fprintf(stderr, "[DEBUG] volumeStore retry body (first 500):\n%.500s\n", retryRes.body.c_str());
            }
            PlistDict retryData = decode_plist(retryRes.body);

            // If volumeStore still returns 5002 after the retry, the failure is
            // not transient — the account has no license for this app.
            // Throw LicenseRequired so the --purchase flag can acquire it.
            if (dict_str(retryData, "failureType") == FAILURE_ALREADY_PURCHASED) {
                if (m_debug)
                    fprintf(stderr,
                        "[DEBUG] volumeStore retry still 5002 — no license, "
                        "throwing LicenseRequired\n");
                throw LicenseRequired();
            }

            return retryData;
        }

        // Redownload has a result (non-empty songList) → use it
        return rdData;
    }

    return data;
}

// ── Redownload / updateProduct (port of upstream appstore_download_product.go)

static constexpr const char* UPDATE_PRODUCT_URL =
    "https://downloaddispatch.itunes.apple.com/up/updateProduct";

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

// Upstream isEmptyRedownloadError: HTTP 500 with an empty body.
static bool is_empty_redownload_error(const HttpResponse& res) {
    return res.statusCode == 500 && trim_copy(res.body).empty();
}

// Upstream isUnavailableDownloadProductResponse: 200, no failureType, no items,
// customerMessage "No Longer Available" (optionally prefixed).
static bool is_unavailable_response(const HttpResponse& res, const PlistDict& d) {
    if (res.statusCode != 200 || !dict_str(d, "failureType").empty()
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

// Headers and payload exactly as upstream downloadProductRequest.
static std::map<std::string, std::string> go_download_headers(const Account& acc) {
    return {
        {"Content-Type", "application/x-apple-plist"},
        {"iCloud-DSID",  acc.directoryServicesID},
        {"X-Dsid",       acc.directoryServicesID},
    };
}

static std::string go_download_payload(const std::string& guid, const App& app,
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

PlistDict AppStore::redownload_product(const Account& acc, const App& app,
                                       const std::string& guid,
                                       const std::string& redownloadEndpoint,
                                       const std::string& externalVersionID,
                                       bool isMac, const char* label)
{
    // Unpinned redownloads can fail or return a tvOS package — pin iOS builds.
    std::string pin = isMac ? externalVersionID
                            : redownload_version_id(acc, app, externalVersionID);

    auto        hdrs = go_download_headers(acc);
    std::string body = go_download_payload(guid, app, pin);
    std::string url  = redownloadEndpoint + "?guid=" + guid;

    if (m_debug) debug_dump_request(label, "POST", url, hdrs, body);
    HttpResponse res = m_http.post(url, body, hdrs);
    if (m_debug) debug_dump_response(label, res);

    PlistDict data = decode_plist_safe(res.body);

    // The bag's updateProduct can serve pinned versions when redownload returns
    // an empty HTTP 500 or a message-only availability error.
    if ((is_empty_redownload_error(res) || is_unavailable_response(res, data))
        && !pin.empty())
    {
        if (m_updateEndpoint.empty()) {
            if (m_debug)
                fprintf(stderr, "[DEBUG] redownload failed and bag has no updateProduct"
                                " — no update fallback\n");
            return data;
        }
        if (m_debug)
            fprintf(stderr, "[DEBUG] redownload failed — trying updateProduct\n");
        return send_update_product(acc, app, guid, pin);
    }
    return data;
}

PlistDict AppStore::send_update_product(const Account& acc, const App& app,
                                        const std::string& guid,
                                        const std::string& externalVersionID)
{
    // Upstream newDownloadEndpoint: only the exact downloaddispatch path is accepted.
    if (m_updateEndpoint != UPDATE_PRODUCT_URL)
        throw IpaError("invalid download endpoint in bag: " + m_updateEndpoint);

    auto        hdrs = go_download_headers(acc);
    std::string body = go_download_payload(guid, app, externalVersionID);
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

// ── Bag (fetch auth + redownload endpoints) ──────────────────────────────

AppStore::BagOutput AppStore::fetch_bag_impl(const std::string& guid) {
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
        out.redownloadEndpoint = dict_str(ubIt->second.dictVal, "redownloadProduct");
        out.updateEndpoint     = dict_str(ubIt->second.dictVal, "updateProduct");
        m_updateEndpoint       = out.updateEndpoint;

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

std::string AppStore::fetch_bag_auth_endpoint(const std::string& guid) {
    return fetch_bag_impl(guid).authEndpoint;
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
    debug_dump_response("authenticate", res);
}

Account AppStore::do_login(const std::string& email,
                 const std::string& password,
                 const std::string& authCode,
                 const std::string& guid,
                 const std::string& baseEndpoint,
                 SapSigner* signer)
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
        if (signer) {
            try {
                auto sigBytes = signer->Sign(std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(body.data()), body.size()));
                headers[HTTP_HEADER_SAP_SIGNATURE] = SapBase64::Encode(sigBytes);
                if (m_debug)
                    fprintf(stderr, "[DEBUG] SAP signature: %zu bytes\n", sigBytes.size());
            } catch (const std::exception& e) {
                if (m_debug)
                    fprintf(stderr, "[DEBUG] SAP sign failed: %s\n", e.what());
            }
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

    HttpResponse res  = m_http.post(url, encode_plist_xml(payload), headers);
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
    fs::copy_file(srcPath, dstPath,
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
        std::ifstream in(srcPath,  std::ios::binary);
        std::ofstream out(dstPath, std::ios::binary | std::ios::trunc);
        if (!in)  throw IpaError("minizip: cannot open source IPA");
        if (!out) throw IpaError("minizip: cannot create output IPA");
        out << in.rdbuf();
    }

    // ── Step 2: collect bundle info needed for sinf path ─────────────────
    std::string bundleName;
    std::string bundleExecutable;
    std::vector<std::string> sinfPaths;

    if (!sinfs.empty()) {
        unzFile probe = unzOpen(srcPath.c_str());
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
    zipFile dst = zipOpen(dstPath.c_str(), APPEND_STATUS_ADDINZIP);
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
                                       const std::string& outputPath)
{
    std::string fname = make_filename(app, version);
    if (outputPath.empty()) {
        return (fs::current_path() / fname).string();
    }
    fs::path p(outputPath);
    if (fs::is_directory(p)) return (p / fname).string();
    return outputPath;
}

std::string AppStore::make_filename(const App& app, const std::string& version) {
    std::string name;
    if (!app.bundleID.empty()) name += app.bundleID;
    if (app.id > 0) {
        if (!name.empty()) name += "_";
        name += std::to_string(app.id);
    }
    if (!version.empty()) {
        if (!name.empty()) name += "_";
        name += version;
    }
    return name + ".ipa";
}

int64_t AppStore::file_size(const std::string& path) {
    std::error_code ec;
    auto sz = fs::file_size(path, ec);
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

// ═══════════════════════════════════════════════════════════════════════════
//  download_mac — macOS .pkg download + StoreAgent decryption (v2.4.0+)
// ═══════════════════════════════════════════════════════════════════════════
static std::vector<uint8_t> mac_extract_dpinfo(const std::vector<Sinf>& sinfs) {
    std::vector<uint8_t> dpInfo;
    for (const auto& s : sinfs) {
        if (s.dpInfo.empty()) continue;
        if (!dpInfo.empty() && dpInfo != s.dpInfo)
            throw IpaError("download response contains conflicting dpInfo values");
        dpInfo = s.dpInfo;
    }
    if (dpInfo.empty())
        throw IpaError("download response does not contain dpInfo (not a macOS app?)");
    return dpInfo;
}

AppStore::DownloadOutput AppStore::download_mac(const Account& acc, const App& app,
                                      const std::string& outputPath,
                                      ProgressCb progress,
                                      const std::string& redownloadEndpoint)
{
    // 1. Get guid / hardware ID
    std::string guid = get_guid();
    auto hardwareID  = SapSigner::LocalHardwareID();
    if (hardwareID.empty())
        throw IpaError("failed to get hardware ID for macOS download");

    // 2. Download request (same as iOS but pkg extension)
    PlistDict dlData = send_download_product(acc, app, guid, "", redownloadEndpoint,
                                             /*isMac=*/true);

    auto songList = dict_arr(dlData, "songList");
    if (songList.empty()) throw IpaError("invalid response: empty songList");
    auto& itemVal = songList[0];
    if (!itemVal.isDict()) throw IpaError("invalid response: bad songList item");
    const PlistDict& item = itemVal.dictVal;

    std::string downloadURL = dict_str(item, "URL");
    if (downloadURL.empty()) throw IpaError("no download URL in response");

    // Parse sinfs to get dpInfo
    std::vector<Sinf> sinfs;
    auto sinfsIt = item.find("sinfs");
    if (sinfsIt != item.end() && sinfsIt->second.isArray()) {
        for (auto& sv : sinfsIt->second.arrayVal) {
            if (!sv.isDict()) continue;
            Sinf s;
            auto dit  = sv.dictVal.find("sinf");
            if (dit  != sv.dictVal.end() && dit->second.isData()) s.data   = dit->second.dataVal;
            auto dpit = sv.dictVal.find("dpInfo");
            if (dpit != sv.dictVal.end() && dpit->second.isData()) s.dpInfo = dpit->second.dataVal;
            sinfs.push_back(std::move(s));
        }
    }

    auto dpInfo = mac_extract_dpinfo(sinfs);
    if (m_debug)
        fprintf(stderr, "[DEBUG] macOS dpInfo: %zu bytes\n", dpInfo.size());

    // 3. Resolve output path (.pkg extension)
    std::string version = "unknown";
    {
        auto meta = item.find("metadata");
        if (meta != item.end() && meta->second.isDict()) {
            auto vit = meta->second.dictVal.find("bundleShortVersionString");
            if (vit != meta->second.dictVal.end() && vit->second.isString())
                version = vit->second.strVal;
        }
    }

    std::string dest = outputPath;
    {
        std::error_code _ec;
        bool isDir = !dest.empty() && std::filesystem::is_directory(dest, _ec);
        if (dest.empty() || isDir) {
        std::string fname = app.bundleID + "_" + std::to_string(app.id) + "_" + version + ".pkg";
        dest = (dest.empty() || isDir) ? (isDir ? dest + "/" + fname : fname) : dest;
        if (!isDir && dest.find(".pkg") == std::string::npos) dest += ".pkg";
    }
    }

    std::string encPath = dest + ".ipatool-encrypted";
    std::string decPath = dest + ".ipatool-decrypted";

    // Cleanup staging on exit
    auto cleanup = [&](bool success) {
        std::error_code ec;
        std::filesystem::remove(encPath, ec);
        if (!success) std::filesystem::remove(decPath, ec);
    };

    // 4. Download encrypted .pkg
    if (m_debug) fprintf(stderr, "[DEBUG] macOS download → %s\n", encPath.c_str());
    m_http.download(downloadURL, encPath, 0, progress);

    // 5. Initialize StoreAgentMachine
    if (m_debug) fprintf(stderr, "[DEBUG] loading StoreAgent assets...\n");
    auto machine = StoreAgentMachine::Create(
        load_sap_asset("CoreFP"),
        load_sap_asset("CommerceCore"),
        load_sap_asset("CommerceKit"),
        load_sap_asset("CoreFP.icxs"),
        load_sap_asset("storeagent")
    );

    uint32_t globalCtx = machine->InitializeGlobal(hardwareID);
    uint64_t session   = machine->InitializeSession(globalCtx, dpInfo);
    if (m_debug) fprintf(stderr, "[DEBUG] StoreAgent session ready, decrypting...\n");

    // 6. Stream-decrypt 32KB chunks
    {
        std::ifstream src_f(encPath, std::ios::binary);
        std::ofstream dst_f(decPath, std::ios::binary | std::ios::trunc);
        if (!src_f) throw IpaError("failed to open encrypted pkg: " + encPath);
        if (!dst_f) throw IpaError("failed to open decrypted pkg: " + decPath);

        std::vector<uint8_t> buf(StoreAgentMachine::kChunkSize);
        while (true) {
            src_f.read(reinterpret_cast<char*>(buf.data()), buf.size());
            std::streamsize n = src_f.gcount();
            if (n == 0) break;

            std::span<uint8_t> chunk(buf.data(), static_cast<size_t>(n));
            machine->DecryptChunk(session, chunk);
            dst_f.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        }
    }

    machine->CloseSession(session);

    // 7. Publish: atomic rename decrypted → final destination
    {
        std::error_code ec;
        std::filesystem::rename(decPath, dest, ec);
        if (ec) {
            // Fallback: copy then remove
            std::filesystem::copy_file(decPath, dest,
                std::filesystem::copy_options::overwrite_existing, ec);
            if (ec) throw IpaError("failed to publish pkg: " + ec.message());
            std::filesystem::remove(decPath, ec);
        }
    }

    cleanup(true);
    if (m_debug) fprintf(stderr, "[DEBUG] macOS pkg saved: %s\n", dest.c_str());
    return { dest, sinfs };
}
