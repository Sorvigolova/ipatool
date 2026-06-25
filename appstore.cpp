#include "appstore.h"
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

// ─────────────────────────────────────────────────────────────────────────────
// Storefront → country code
// ─────────────────────────────────────────────────────────────────────────────

// Plain array, not std::map: lookup below scans by *id* (the value), never by
// *cc* (what would be the map key), so std::map's O(log n) keyed lookup was
// never actually used — just extra allocation/rebalancing for no benefit.
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

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Login (GSA path — replaces broken iTunes fast-auth endpoint)
// ─────────────────────────────────────────────────────────────────────────────

Account AppStore::login(const std::string&  email,
                        const std::string&  password,
                        const AnisetteData& anisette,
                        const std::string&  authCode)
{
    GsaClient gsa(m_http, m_debug);
    Account acc = gsa.login(email, password, anisette, authCode);

    // PET expires in 5 min — exchange it for iTunes auth cookies immediately,
    // while it is still fresh. Cookies go into COOKIE_FILE for later requests.
    const std::string guid = get_guid();
    try {
        do_itunes_auth(acc, anisette, guid);
    } catch (const std::exception& e) {
        fprintf(stderr, "[WARN] iTunes auth failed: %s\n", e.what());
    }
    return acc;
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Search / Lookup
// ─────────────────────────────────────────────────────────────────────────────

AppStore::SearchOutput AppStore::search(const Account& acc, const std::string& term, int limit) {
    std::string cc  = country_code_from_storefront(acc.storeFront);
    std::string url = search_url(term, cc, limit);

    if (m_debug) fprintf(stderr, "[DEBUG] search URL: %s\n", url.c_str());
    HttpResponse res = m_http.get(url);
    if (m_debug) {
        fprintf(stderr, "[DEBUG] search status: %d\n", res.statusCode);
        fprintf(stderr, "[DEBUG] search body:\n%s\n", res.body.c_str());
    }
    if (res.statusCode != 200)
        throw IpaError("search request failed: " + std::to_string(res.statusCode));

    auto sr = parse_search_json(res.body);
    return {sr.count, sr.results};
}

App AppStore::lookup(const Account& acc, const std::string& bundleID) {
    std::string cc  = country_code_from_storefront(acc.storeFront);
    std::string url = lookup_url(bundleID, cc);

    if (m_debug) fprintf(stderr, "[DEBUG] lookup URL: %s\n", url.c_str());
    HttpResponse res = m_http.get(url);
    if (m_debug) {
        fprintf(stderr, "[DEBUG] lookup status: %d\n", res.statusCode);
        fprintf(stderr, "[DEBUG] lookup body:\n%s\n", res.body.c_str());
    }
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

    if (m_debug) fprintf(stderr, "[DEBUG] lookup-by-id URL: %s\n", url.c_str());
    HttpResponse res = m_http.get(url);
    if (m_debug) {
        fprintf(stderr, "[DEBUG] lookup-by-id status: %d\n", res.statusCode);
        fprintf(stderr, "[DEBUG] lookup-by-id body:\n%s\n", res.body.c_str());
    }
    if (res.statusCode != 200)
        throw IpaError("lookup request failed: " + std::to_string(res.statusCode));

    auto sr = parse_search_json(res.body);
    if (sr.results.empty()) throw IpaError("app not found");
    return sr.results[0];
}

// ─────────────────────────────────────────────────────────────────────────────
// AppStore — Purchase
// ─────────────────────────────────────────────────────────────────────────────

void AppStore::purchase(const Account& acc, const App& app) {
    if (app.price > 0.0) throw PaidAppNotSupported();
    std::string guid = get_guid();
    try {
        do_purchase(acc, app, guid, PRICING_APPSTORE);
    } catch (const IpaError& e) {
        if (std::string(e.what()).find("temporarily unavailable") != std::string::npos) {
            do_purchase(acc, app, guid, PRICING_ARCADE);
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
                        ProgressCb progress)
{
    std::string guid = get_guid();

    PlistDict payload;
    payload["creditDisplay"] = PlistValue::makeString("");
    payload["guid"]          = PlistValue::makeString(guid);
    payload["salableAdamId"] = PlistValue::makeInt(app.id);
    payload["serialNumber"]  = PlistValue::makeString("0");
    if (!externalVersionID.empty())
        payload["externalVersionId"] = PlistValue::makeString(externalVersionID);

    std::string pod_prefix;
    if (!acc.pod.empty()) pod_prefix = "p" + acc.pod + "-";
    std::string vsUrl = "https://" + pod_prefix + std::string(PRIVATE_AS_DOMAIN)
                        + PRIVATE_AS_PATH_DOWNLOAD + "?guid=" + guid;

    if (m_debug)
        fprintf(stderr, "[DEBUG] download URL: %s\n", vsUrl.c_str());

    std::map<std::string, std::string> headers = {
        {"Content-Type", "application/x-apple-plist"},
        {"iCloud-DSID",  acc.directoryServicesID},
        {"X-Dsid",       acc.directoryServicesID},
    };

    HttpResponse vsRes = m_http.post(vsUrl, encode_plist_xml(payload), headers);
    if (m_debug) {
        fprintf(stderr, "[DEBUG] volumeStore status: %d\n", vsRes.statusCode);
        fprintf(stderr, "[DEBUG] volumeStore body:\n%s\n", vsRes.body.c_str());
    }
    PlistDict   data        = decode_plist(vsRes.body);
    std::string failureType = dict_str(data, "failureType");

    std::string customerMessage = dict_str(data, "customerMessage");

    if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED) throw PasswordTokenExpired();
    if (customerMessage == CUSTOMER_MSG_SIGN_IN)       throw PasswordTokenExpired();
    if (failureType == FAILURE_LICENSE_NOT_FOUND)      throw LicenseRequired();
    if (!failureType.empty() && !customerMessage.empty())
        throw IpaError("received error: " + customerMessage);
    if (!failureType.empty())
        throw IpaError("received error: " + failureType);

    auto songList = dict_arr(data, "songList");
    if (songList.empty()) throw IpaError("invalid response: empty songList");

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
            if (dit != sv.dictVal.end() && dit->second.isData())
                s.data = dit->second.dataVal;
            sinfs.push_back(std::move(s));
        }
    }

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

PlistDict AppStore::fetch_download_info(const Account& acc, const std::string& guid,
                              int64_t adamId, const std::string& versionId)
{
    std::string pod_prefix;
    if (!acc.pod.empty()) pod_prefix = "p" + acc.pod + "-";
    std::string vsUrl = "https://" + pod_prefix + std::string(PRIVATE_AS_DOMAIN)
                        + PRIVATE_AS_PATH_DOWNLOAD + "?guid=" + guid;

    std::map<std::string, std::string> headers = {
        {"Content-Type", "application/x-apple-plist"},
        {"iCloud-DSID",  acc.directoryServicesID},
        {"X-Dsid",       acc.directoryServicesID},
    };

    PlistDict payload;
    payload["creditDisplay"]  = PlistValue::makeString("");
    payload["guid"]           = PlistValue::makeString(guid);
    payload["salableAdamId"]  = PlistValue::makeInt(adamId);
    payload["serialNumber"]   = PlistValue::makeString("0");
    if (!versionId.empty())
        payload["externalVersionId"] = PlistValue::makeString(versionId);

    HttpResponse res = m_http.post(vsUrl, encode_plist_xml(payload), headers);
    PlistDict    data = decode_plist(res.body);

    if (m_debug)
        fprintf(stderr, "[fetch] volumeStoreDownloadProduct → failureType=%s songList=%zu\n",
                dict_str(data, "failureType").c_str(),
                dict_arr(data, "songList").size());

    if (dict_str(data, "failureType") == FAILURE_LICENSE_NOT_FOUND)
        throw LicenseRequired();

    return data;
}

AppStore::ListVersionsOutput AppStore::list_versions(const Account& acc, const App& app) {
    std::string guid = get_guid();
    PlistDict   data = fetch_download_info(acc, guid, app.id);

    std::string failureType     = dict_str(data, "failureType");
    std::string customerMessage = dict_str(data, "customerMessage");
    if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED) throw PasswordTokenExpired();
    if (customerMessage == CUSTOMER_MSG_SIGN_IN)       throw PasswordTokenExpired();
    if (failureType == FAILURE_LICENSE_NOT_FOUND)      throw LicenseRequired();
    if (!failureType.empty() && !customerMessage.empty())
        throw IpaError("received error: " + customerMessage);
    if (!failureType.empty())
        throw IpaError("received error: " + failureType);

    auto songList = dict_arr(data, "songList");
    if (songList.empty()) throw IpaError("invalid response: empty songList");
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
}

AppStore::GetVersionMetadataOutput AppStore::get_version_metadata(const Account& acc,
                                               const App& app,
                                               const std::string& versionID) {
    std::string guid = get_guid();
    PlistDict   data = fetch_download_info(acc, guid, app.id, versionID);

    std::string failureType     = dict_str(data, "failureType");
    std::string customerMessage = dict_str(data, "customerMessage");
    if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED) throw PasswordTokenExpired();
    if (customerMessage == CUSTOMER_MSG_SIGN_IN)       throw PasswordTokenExpired();
    if (failureType == FAILURE_LICENSE_NOT_FOUND)      throw LicenseRequired();
    if (!failureType.empty() && !customerMessage.empty())
        throw IpaError("received error: " + customerMessage);
    if (!failureType.empty())
        throw IpaError("received error: " + failureType);

    auto songList = dict_arr(data, "songList");
    if (songList.empty()) throw IpaError("invalid response: empty songList");
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

std::string AppStore::get_guid() { return get_guid_from_mac(); }

std::string AppStore::get_guid_from_mac() {
#ifdef _WIN32
    // Windows: enumerate adapters via iphlpapi
    ULONG bufLen = sizeof(IP_ADAPTER_INFO);
    std::vector<BYTE> buf(bufLen);
    if (GetAdaptersInfo(reinterpret_cast<PIP_ADAPTER_INFO>(buf.data()), &bufLen)
            == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
    }
    PIP_ADAPTER_INFO adapter =
        reinterpret_cast<PIP_ADAPTER_INFO>(buf.data());
    if (GetAdaptersInfo(adapter, &bufLen) == NO_ERROR) {
        while (adapter) {
            // Skip loopback (address = 00:00:00:00:00:00) and software adapters
            bool allZero = true;
            for (UINT i = 0; i < adapter->AddressLength; i++)
                if (adapter->Address[i]) { allZero = false; break; }
            if (!allZero && adapter->AddressLength == 6) {
                char buf2[32];
                snprintf(buf2, sizeof(buf2),
                    "%02X%02X%02X%02X%02X%02X",
                    adapter->Address[0], adapter->Address[1],
                    adapter->Address[2], adapter->Address[3],
                    adapter->Address[4], adapter->Address[5]);
                return std::string(buf2);
            }
            adapter = adapter->Next;
        }
    }
#elif defined(__APPLE__) || defined(__linux__)
    // POSIX: walk interface addresses
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) == 0) {
        for (struct ifaddrs* ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
#  ifdef __APPLE__
            if (ifa->ifa_addr->sa_family != AF_LINK) continue;
            auto* sdl = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
            if (sdl->sdl_alen != 6) continue;
            unsigned char* mac = reinterpret_cast<unsigned char*>(
                LLADDR(sdl));
#  else // Linux
            if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
            auto* sll = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
            if (sll->sll_halen != 6) continue;
            unsigned char* mac = sll->sll_addr;
#  endif
            // Skip loopback
            bool allZero = (mac[0]|mac[1]|mac[2]|mac[3]|mac[4]|mac[5]) == 0;
            if (allZero) continue;
            char buf2[32];
            snprintf(buf2, sizeof(buf2),
                "%02X%02X%02X%02X%02X%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            freeifaddrs(ifap);
            return std::string(buf2);
        }
        freeifaddrs(ifap);
    }
#endif
    return "AABBCCDDEEFF"; // fallback
}

// ── iTunes Store authentication (GSA path) ───────────────────────────────

void AppStore::do_itunes_auth(Account& acc,
                    const AnisetteData& anisette,
                    const std::string& guid)
{
    if (acc.petToken.empty()) {
        fprintf(stderr, "[iTunes auth] no PET token — re-run auth login\n");
        return;
    }

    // X-Apple-Identity-Token = base64(adsid:GsIdmsToken)
    const std::string raw_id  = acc.adsid + ":" + acc.gsIdmsToken.get();
    const std::string id_tok  = base64_encode(
        reinterpret_cast<const unsigned char*>(raw_id.data()), raw_id.size());

    // Body — exact field set from gsa.js storeAuthenticate()
    PlistDict payload;
    payload["appleId"]       = PlistValue::makeString(acc.email);
    payload["attempt"]       = PlistValue::makeString("1");
    payload["createSession"] = PlistValue::makeString("true");
    payload["guid"]          = PlistValue::makeString(guid);
    payload["password"]      = PlistValue::makeString(acc.petToken); // PET as password
    payload["rmp"]           = PlistValue::makeString("0");
    payload["why"]           = PlistValue::makeString("signIn");

    // Headers — anisette + identity token (no X-Dsid, no X-Apple-Store-Front yet)
    std::map<std::string, std::string> hdrs = {
        {"Content-Type",            "application/x-apple-plist"},
        {"X-Apple-I-MD",            anisette.otp},
        {"X-Apple-I-MD-M",          anisette.machineID},
        {"X-Apple-I-MD-RINFO",      anisette.routingInfo},
        {"X-Apple-I-MD-LU",         anisette.localUserUUID},
        {"X-Mme-Device-Id",         anisette.deviceID},
        {"X-Apple-I-Client-Time",   anisette.clientTime},
        {"X-Apple-I-TimeZone",      anisette.timezone},
        {"X-Apple-Identity-Token",  id_tok},
    };

    // URL: hardcoded constant, no ?guid, no pod prefix (first call)
    static const char* AUTH_URL =
        "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate";

    HttpResponse res = m_http.post(AUTH_URL, encode_plist_xml(payload), hdrs);

    // Apple may redirect (302) to pod-specific URL e.g. p51-buy.itunes.apple.com
    // gsa.js uses curl -L --post302 to follow with POST — we do it manually
    if (res.statusCode == 301 || res.statusCode == 302 || res.statusCode == 307) {
        auto locIt = res.headers.find("location");
        if (locIt != res.headers.end() && !locIt->second.empty()) {
            if (m_debug)
                fprintf(stderr, "[iTunes auth] redirect → %s\n", locIt->second.c_str());
            res = m_http.post(locIt->second, encode_plist_xml(payload), hdrs);
        }
    }

    if (m_debug) {
        fprintf(stderr, "[iTunes auth] status=%d\n", res.statusCode);
        fprintf(stderr, "[iTunes auth] response headers:\n");
        for (auto& [k, v] : res.headers)
            fprintf(stderr, "  %s: %s\n", k.c_str(), v.c_str());
        fprintf(stderr, "[iTunes auth] body:\n%s\n", res.body.c_str());
    }
    if (res.statusCode != 200 && res.statusCode != 201)
        throw IpaError("iTunes auth: HTTP " + std::to_string(res.statusCode));

    // Parse response — extract passwordToken and dsPersonId
    PlistDict resp = decode_plist(res.body);
    const std::string pt  = dict_str(resp, "passwordToken");
    const std::string dsp = dict_str(resp, "dsPersonId");

    if (m_debug)
        fprintf(stderr, "[iTunes auth] passwordToken=%s dsPersonId=%s\n",
                pt.empty() ? "(empty)" : (pt.substr(0,20)+"...").c_str(),
                dsp.c_str());

    if (pt.empty()) {
        const std::string msg = dict_str(resp, "customerMessage");
        throw IpaError("[iTunes auth] no passwordToken — " +
                       (msg.empty() ? "unknown error" : msg));
    }

    // Store iTunes Store passwordToken (replaces GsIdmsToken for subsequent store ops)
    acc.passwordToken.set(pt);
    if (!dsp.empty())
        acc.directoryServicesID = dsp;

    // Extract pod from response headers (itspod: 51 or pod: 51)
    auto podIt = res.headers.find("pod");
    if (podIt == res.headers.end()) podIt = res.headers.find("itspod");
    if (podIt != res.headers.end() && !podIt->second.empty())
        acc.pod = podIt->second;

    // Extract storeFront from x-set-apple-store-front header
    auto sfIt = res.headers.find("x-set-apple-store-front");
    if (sfIt != res.headers.end() && !sfIt->second.empty())
        acc.storeFront = sfIt->second;

    if (m_debug)
        fprintf(stderr, "[iTunes auth] pod=%s storeFront=%s\n",
                acc.pod.c_str(), acc.storeFront.c_str());

    // Dump cookie file to verify mz_at0 was set
    if (m_debug && !m_http.cookie_file().empty()) {
        fprintf(stderr, "[iTunes auth] cookie file contents:\n");
        FILE* f = fopen(m_http.cookie_file().c_str(), "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f))
                if (strstr(line, "mz_at") || strstr(line, "itspod") || strstr(line, "hsaccnt"))
                    fprintf(stderr, "  %s", line);
            fclose(f);
        }
    }
}


// ── Purchase implementation ───────────────────────────────────────────────

void AppStore::do_purchase(const Account& acc, const App& app,
                 const std::string& guid, const std::string& pricingParam,
                 std::map<std::string,std::string> headers)
{
    std::string pod_prefix;
    if (!acc.pod.empty()) pod_prefix = "p" + acc.pod + "-";

    std::string url = "https://" + pod_prefix + std::string(PRIVATE_AS_DOMAIN)
                    + PRIVATE_AS_PATH_PURCHASE;

    PlistDict payload;
    payload["appExtVrsId"]               = PlistValue::makeString("0");
    payload["buyWithoutAuthorization"]   = PlistValue::makeString("true");
    payload["guid"]                      = PlistValue::makeString(guid);
    payload["needDiv"]                   = PlistValue::makeString("0");
    payload["ownerDsid"]                 = PlistValue::makeString(acc.directoryServicesID);
    payload["pg"]                        = PlistValue::makeString("default");
    payload["price"]                     = PlistValue::makeString("0");
    payload["pricingParameters"]         = PlistValue::makeString(pricingParam);
    payload["productType"]               = PlistValue::makeString("C");
    payload["salableAdamId"]             = PlistValue::makeInt(app.id);

    // Use passed-in headers (with anisette), or build minimal headers as fallback
    if (headers.empty()) {
        headers = {
            {"Content-Type",        "application/x-apple-plist"},
            {"X-Dsid",              acc.directoryServicesID},
            {"X-Apple-Store-Front", acc.storeFront},
            {"X-Token",             acc.passwordToken.get()},
        };
    }

    HttpResponse res  = m_http.post(url, encode_plist_xml(payload), headers);
    PlistDict    data  = decode_plist(res.body);

    std::string failureType     = dict_str(data, "failureType");
    std::string customerMessage = dict_str(data, "customerMessage");
    std::string jingleDocType   = dict_str(data, "jingleDocType");
    int64_t     status          = dict_int(data, "status");

    if (m_debug) {
        fprintf(stderr, "[DEBUG] buyProduct status=%d jingle=%s failureType=%s\n",
                res.statusCode, jingleDocType.c_str(), failureType.c_str());
        fprintf(stderr, "[DEBUG] buyProduct body:\n%s\n", res.body.c_str());
    }

    if (failureType == FAILURE_TEMPORARILY_UNAVAILABLE)   throw IpaError("item is temporarily unavailable");
    if (customerMessage == CUSTOMER_MSG_SUBSCRIPTION_REQ) throw SubscriptionRequired();
    if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED)    throw PasswordTokenExpired();
    if (customerMessage == CUSTOMER_MSG_SIGN_IN)          throw PasswordTokenExpired();
    if (!failureType.empty() && !customerMessage.empty()
        && failureType != FAILURE_ALREADY_PURCHASED)      throw IpaError(customerMessage);
    if (!failureType.empty() && failureType != FAILURE_ALREADY_PURCHASED)
                                                          throw IpaError("something went wrong");
    if (failureType == FAILURE_ALREADY_PURCHASED)         throw AlreadyPurchased();
    if (jingleDocType != "purchaseSuccess" || status != 0)
        throw IpaError("failed to purchase app");
}

// ── ZIP patching ──────────────────────────────────────────────────────────
// Injects a patched iTunesMetadata.plist into the downloaded IPA.
// Uses minizip when available; falls back to a pure C++ copy without patching.

// ── IPA patching — matches original applyPatches + ReplicateSinf ────────
//
// Step 1 (applyPatches): rewrite iTunesMetadata.plist with apple-id/userName
// Step 2 (replicateSinf): inject sinf file(s) into Payload/App.app/SC_Info/
//   - If SC_Info/Manifest.plist exists: use SinfPaths from it (zip with sinfs by index)
//   - Otherwise: write sinfs[0] to SC_Info/{CFBundleExecutable}.sinf
//
// Both steps read from srcPath (.tmp) and write to dstPath (final .ipa),
// matching the two-pass approach in the original Go code.

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

    std::vector<uint8_t> artworkBytes;
    std::string artworkURL = dict_str(item, "artworkURL");
    if (!artworkURL.empty()) {
        HttpResponse artRes = m_http.get(artworkURL);
        if (artRes.statusCode == 200 && !artRes.body.empty())
            artworkBytes.assign(artRes.body.begin(), artRes.body.end());
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
