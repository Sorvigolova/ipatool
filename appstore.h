#pragma once
//
// AppStore — C++ port of ipatool/pkg/appstore
// Cross-platform: Windows (MSVC / VS2022), Linux, macOS
//
#include "ipatool.h"
#include "http_client.h"
#include "plist.h"
#include "json_helpers.h"
#include "storefront.h"

#include <string>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>   // C++17 — replaces getcwd / stat / S_ISDIR

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

// ── URL encode helper ─────────────────────────────────────────────────────────

static std::string url_encode(const std::string& s) {
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

static std::string build_query(const std::map<std::string, std::string>& params) {
    std::string q;
    for (auto& [k, v] : params) {
        if (!q.empty()) q += '&';
        q += url_encode(k) + '=' + url_encode(v);
    }
    return q;
}

// ── AppStore class ────────────────────────────────────────────────────────────

class AppStore {
public:
    // cookieFile: path to store session cookies (persisted between login and download)
    explicit AppStore(const std::string& cookieFile = "")
        : m_http(cookieFile) {}

    // ── Login ────────────────────────────────────────────────────────────────

    Account login(const std::string& email,
                  const std::string& password,
                  const std::string& authCode = "",
                  const std::string& endpoint = "")
    {
        std::string guid = get_guid();
        std::string loginEndpoint = endpoint.empty()
                                  ? fetch_bag_auth_endpoint(guid)
                                  : endpoint;
        return do_login(email, password, authCode, guid, loginEndpoint);
    }

    // ── Search ───────────────────────────────────────────────────────────────

    struct SearchOutput {
        int              count = 0;
        std::vector<App> results;
    };

    SearchOutput search(const Account& acc, const std::string& term, int limit = 5) {
        std::string cc  = country_code_from_storefront(acc.storeFront);
        std::string url = search_url(term, cc, limit);

        HttpResponse res = m_http.get(url);
        if (res.statusCode != 200)
            throw IpaError("search request failed: " + std::to_string(res.statusCode));

        auto sr = parse_search_json(res.body);
        return {sr.count, sr.results};
    }

    // ── Lookup by bundle ID ───────────────────────────────────────────────────

    App lookup(const Account& acc, const std::string& bundleID) {
        std::string cc  = country_code_from_storefront(acc.storeFront);
        std::string url = lookup_url(bundleID, cc);

        HttpResponse res = m_http.get(url);
        if (res.statusCode != 200)
            throw IpaError("lookup request failed: " + std::to_string(res.statusCode));

        auto sr = parse_search_json(res.body);
        if (sr.results.empty()) throw IpaError("app not found");
        return sr.results[0];
    }

    // ── Purchase (free apps) ──────────────────────────────────────────────────

    void purchase(const Account& acc, const App& app) {
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

    // ── Download ──────────────────────────────────────────────────────────────

    struct DownloadOutput {
        std::string       destinationPath;
        std::vector<Sinf> sinfs;
    };

    DownloadOutput download(const Account& acc,
                            const App& app,
                            const std::string& outputPath = "",
                            const std::string& externalVersionID = "",
                            ProgressCb progress = nullptr)
    {
        std::string guid = get_guid();

        PlistDict payload;
        payload["creditDisplay"] = PlistValue::makeString("");
        payload["guid"]          = PlistValue::makeString(guid);
        payload["salableAdamId"] = PlistValue::makeInt(app.id);
        if (!externalVersionID.empty())
            payload["externalVersionId"] = PlistValue::makeString(externalVersionID);

        std::string pod_prefix;
        if (!acc.pod.empty()) pod_prefix = "p" + acc.pod + "-";

        std::string url = "https://" + pod_prefix + std::string(PRIVATE_AS_DOMAIN)
                        + PRIVATE_AS_PATH_DOWNLOAD + "?guid=" + guid;

        if (m_debug) {
            fprintf(stderr, "[DEBUG] download URL: %s\n", url.c_str());
            fprintf(stderr, "[DEBUG] dsid: %s\n", acc.directoryServicesID.c_str());
            fprintf(stderr, "[DEBUG] storefront: '%s'\n", acc.storeFront.c_str());
            fprintf(stderr, "[DEBUG] passwordToken length: %zu\n", acc.passwordToken.get().size());
            fprintf(stderr, "[DEBUG] pod: '%s'\n", acc.pod.c_str());
        }

        std::map<std::string, std::string> headers = {
            {"Content-Type", "application/x-apple-plist"},
            {"iCloud-DSID",  acc.directoryServicesID},
            {"X-Dsid",       acc.directoryServicesID},
        };

        HttpResponse res  = m_http.post(url, encode_plist_xml(payload), headers);

        if (m_debug) {
            fprintf(stderr, "[DEBUG] download response status: %d\n", res.statusCode);
            fprintf(stderr, "[DEBUG] download response body (first 500 chars):\n%.500s\n",
                    res.body.c_str());
        }

        PlistDict    data  = decode_plist(res.body);

        std::string failureType     = dict_str(data, "failureType");
        std::string customerMessage = dict_str(data, "customerMessage");

        if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED) throw PasswordTokenExpired();
        if (customerMessage == CUSTOMER_MSG_SIGN_IN)        throw PasswordTokenExpired();
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

public:
    void set_debug(bool v) { m_debug = v; }

    // ── List Versions ────────────────────────────────────────────────────────
    struct ListVersionsOutput {
        std::vector<std::string> externalVersionIdentifiers;
        std::string              latestExternalVersionID;
    };

    ListVersionsOutput list_versions(const Account& acc, const App& app) {
        std::string guid = get_guid();
        std::string pod_prefix;
        if (!acc.pod.empty()) pod_prefix = "p" + acc.pod + "-";
        std::string url = "https://" + pod_prefix + std::string(PRIVATE_AS_DOMAIN)
                        + PRIVATE_AS_PATH_DOWNLOAD + "?guid=" + guid;
        std::map<std::string, std::string> headers = {
            {"Content-Type", "application/x-apple-plist"},
            {"iCloud-DSID",  acc.directoryServicesID},
            {"X-Dsid",       acc.directoryServicesID},
        };

        PlistDict payload;
        payload["creditDisplay"]  = PlistValue::makeString("");
        payload["guid"]           = PlistValue::makeString(guid);
        payload["salableAdamId"]  = PlistValue::makeInt(app.id);

        HttpResponse res = m_http.post(url, encode_plist_xml(payload), headers);
        PlistDict    data = decode_plist(res.body);

        std::string failureType     = dict_str(data, "failureType");
        std::string customerMessage = dict_str(data, "customerMessage");
        if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED) throw PasswordTokenExpired();
        if (customerMessage == CUSTOMER_MSG_SIGN_IN)        throw PasswordTokenExpired();
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

    // ── Get Version Metadata ─────────────────────────────────────────────────
    struct GetVersionMetadataOutput {
        std::string displayVersion;
        std::string releaseDate;
    };

    GetVersionMetadataOutput get_version_metadata(const Account& acc,
                                                   const App& app,
                                                   const std::string& versionID) {
        std::string guid = get_guid();
        std::string pod_prefix;
        if (!acc.pod.empty()) pod_prefix = "p" + acc.pod + "-";
        std::string url = "https://" + pod_prefix + std::string(PRIVATE_AS_DOMAIN)
                        + PRIVATE_AS_PATH_DOWNLOAD + "?guid=" + guid;
        std::map<std::string, std::string> headers = {
            {"Content-Type", "application/x-apple-plist"},
            {"iCloud-DSID",  acc.directoryServicesID},
            {"X-Dsid",       acc.directoryServicesID},
        };

        PlistDict payload;
        payload["creditDisplay"]    = PlistValue::makeString("");
        payload["guid"]             = PlistValue::makeString(guid);
        payload["salableAdamId"]    = PlistValue::makeInt(app.id);
        payload["externalVersionId"] = PlistValue::makeString(versionID);

        HttpResponse res  = m_http.post(url, encode_plist_xml(payload), headers);
        PlistDict    data = decode_plist(res.body);

        std::string failureType     = dict_str(data, "failureType");
        std::string customerMessage = dict_str(data, "customerMessage");
        if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED) throw PasswordTokenExpired();
        if (customerMessage == CUSTOMER_MSG_SIGN_IN)        throw PasswordTokenExpired();
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


private:
    HttpClient m_http;
    bool       m_debug = false;

    // ── MAC address / GUID ───────────────────────────────────────────────────

    static std::string get_guid() {
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

    // ── Bag (fetch auth endpoint) ────────────────────────────────────────────

    std::string fetch_bag_auth_endpoint(const std::string& guid) {
        std::string url = std::string("https://") + PRIVATE_INIT_DOMAIN
                        + PRIVATE_INIT_PATH + "?guid=" + guid;
        HttpResponse res = m_http.get(url, {{"Accept", "application/xml"}});

        if (m_debug) {
            fprintf(stderr, "[DEBUG] bag status: %d\n", res.statusCode);
            fprintf(stderr, "[DEBUG] bag body:\n%s\n", res.body.c_str());
        }

        if (res.statusCode != 200)
            throw IpaError("bag request failed: " + std::to_string(res.statusCode));

        PlistDict d = decode_plist(res.body);

        if (m_debug) {
            fprintf(stderr, "[DEBUG] parsed plist top-level keys:");
            for (auto& [k, v] : d) fprintf(stderr, " '%s'", k.c_str());
            fprintf(stderr, "\n");
        }

        // Try nested: d["urlBag"]["authenticateAccount"]
        auto ubIt = d.find("urlBag");
        if (ubIt != d.end() && ubIt->second.isDict()) {
            std::string ep = dict_str(ubIt->second.dictVal, "authenticateAccount");
            if (!ep.empty()) return ep;
        }

        // Try flat: d["authenticateAccount"] directly
        {
            std::string ep = dict_str(d, "authenticateAccount");
            if (!ep.empty()) return ep;
        }

        // Scan all top-level dict values for authenticateAccount
        for (auto& [k, v] : d) {
            if (v.isDict()) {
                std::string ep = dict_str(v.dictVal, "authenticateAccount");
                if (!ep.empty()) return ep;
            }
        }

        // Fallback to known-good hardcoded endpoint
        fprintf(stderr,
            "[WARN] Could not parse urlBag -- using default auth endpoint.\n"
            "       Retry with --debug to inspect the raw server response.\n");
        return "https://auth.itunes.apple.com/auth/v1/native/fast";
    }

    // ── Login implementation ─────────────────────────────────────────────────

    Account do_login(const std::string& email,
                     const std::string& password,
                     const std::string& authCode,
                     const std::string& guid,
                     const std::string& baseEndpoint)
    {
        std::string  currentURL = baseEndpoint;
        bool         retry      = true;
        HttpResponse lastRes;
        PlistDict    lastData;

        for (int attempt = 1; retry && attempt <= 4; attempt++) {
            PlistDict payload;
            payload["appleId"]  = PlistValue::makeString(email);
            payload["attempt"]  = PlistValue::makeString(std::to_string(attempt));
            payload["guid"]     = PlistValue::makeString(guid);
            payload["password"] = PlistValue::makeString(password + strip_spaces(authCode));
            payload["rmp"]      = PlistValue::makeString("0");
            payload["why"]      = PlistValue::makeString("signIn");

            std::map<std::string, std::string> headers = {
                {"Content-Type", "application/x-www-form-urlencoded"},
            };

            lastRes  = m_http.post(currentURL, encode_plist_xml(payload), headers);
            lastData = decode_plist(lastRes.body);

            std::string failureType     = dict_str(lastData, "failureType");
            std::string customerMessage = dict_str(lastData, "customerMessage");

            if (lastRes.statusCode == 302) {
                auto locIt = lastRes.headers.find("location");
                if (locIt == lastRes.headers.end())
                    throw IpaError("redirect with no location header");
                currentURL = locIt->second;
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

    void do_purchase(const Account& acc, const App& app,
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

        if (failureType == FAILURE_TEMPORARILY_UNAVAILABLE)
            throw IpaError("item is temporarily unavailable");
        if (customerMessage == CUSTOMER_MSG_SUBSCRIPTION_REQ) throw SubscriptionRequired();
        if (failureType == FAILURE_PASSWORD_TOKEN_EXPIRED)    throw PasswordTokenExpired();
        if (customerMessage == CUSTOMER_MSG_SIGN_IN)           throw PasswordTokenExpired();
        if (!failureType.empty() && !customerMessage.empty()) throw IpaError(customerMessage);
        if (!failureType.empty())                             throw IpaError("something went wrong");
        if (res.statusCode == 500)                            throw IpaError("license already exists");
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

    void apply_patches(const PlistDict& item,
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
            char buf[32];
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
    static void patch_with_minizip(const std::string& srcPath,
                                   const std::string& dstPath,
                                   const std::vector<uint8_t>& metaBytes,
                                   const std::vector<uint8_t>& artworkBytes,
                                   const std::vector<Sinf>& sinfs)
    {
        unzFile src = unzOpen(srcPath.c_str());
        if (!src) throw IpaError("minizip: failed to open source IPA");

        zipFile dst = zipOpen(dstPath.c_str(), APPEND_STATUS_CREATE);
        if (!dst) { unzClose(src); throw IpaError("minizip: failed to create output IPA"); }

        // ── Collect info we need before rewriting ────────────────────────────
        std::string bundleName;       // e.g. "Minecraft"  (from .app/Info.plist path)
        std::string bundleExecutable; // CFBundleExecutable from Info.plist
        std::vector<std::string> sinfPaths; // from SC_Info/Manifest.plist

        {
            int rc2 = unzGoToFirstFile(src);
            while (rc2 == UNZ_OK) {
                char name[1024] = {};
                unz_file_info fi2;
                unzGetCurrentFileInfo(src, &fi2, name, sizeof(name), nullptr, 0, nullptr, 0);
                std::string n(name);

                // Read bundle name from first .app/Info.plist (not in Watch/)
                if (bundleName.empty()
                    && n.find(".app/Info.plist") != std::string::npos
                    && n.find("/Watch/") == std::string::npos)
                {
                    // "Payload/Foo.app/Info.plist" -> "Foo"
                    size_t appPos = n.rfind(".app/Info.plist");
                    size_t slashPos = n.rfind('/', appPos - 1);
                    bundleName = n.substr(slashPos + 1, appPos - slashPos - 1);
                }

                // Read Info.plist to get CFBundleExecutable
                if (bundleExecutable.empty()
                    && n.find(".app/Info.plist") != std::string::npos
                    && n.find("/Watch/") == std::string::npos)
                {
                    unzOpenCurrentFile(src);
                    std::vector<uint8_t> buf(fi2.uncompressed_size);
                    unzReadCurrentFile(src, buf.data(), (unsigned)buf.size());
                    unzCloseCurrentFile(src);
                    // parse CFBundleExecutable from binary or XML plist
                    bundleExecutable = extract_plist_string(buf, "CFBundleExecutable");
                }

                // Read SC_Info/Manifest.plist to get SinfPaths
                if (sinfPaths.empty()
                    && n.find(".app/SC_Info/Manifest.plist") != std::string::npos)
                {
                    unzOpenCurrentFile(src);
                    std::vector<uint8_t> buf(fi2.uncompressed_size);
                    unzReadCurrentFile(src, buf.data(), (unsigned)buf.size());
                    unzCloseCurrentFile(src);
                    sinfPaths = extract_sinf_paths(buf);
                }

                rc2 = unzGoToNextFile(src);
            }
            unzGoToFirstFile(src); // rewind
        }

        // Build set of paths that sinf injection will write so we can skip them
        std::set<std::string> sinfWritePaths;
        if (!sinfs.empty() && !bundleName.empty()) {
            if (!sinfPaths.empty()) {
                for (auto& sp : sinfPaths)
                    sinfWritePaths.insert("Payload/" + bundleName + ".app/" + sp);
            } else if (!bundleExecutable.empty()) {
                sinfWritePaths.insert("Payload/" + bundleName + ".app/SC_Info/"
                                      + bundleExecutable + ".sinf");
            }
        }

        // ── Step 1: replicate existing zip, skipping sinf paths that will be replaced ──
        int rc = unzGoToFirstFile(src);
        while (rc == UNZ_OK) {
            char name[1024] = {};
            unz_file_info fi;
            unzGetCurrentFileInfo(src, &fi, name, sizeof(name), nullptr, 0, nullptr, 0);
            std::string n(name);

            bool skip = (sinfWritePaths.count(n) > 0);
            if (!skip) {
                unzOpenCurrentFile(src);
                std::vector<uint8_t> buf(fi.uncompressed_size);
                unzReadCurrentFile(src, buf.data(), (unsigned)buf.size());
                unzCloseCurrentFile(src);

                zip_fileinfo zfi = {};
                zfi.tmz_date.tm_year = fi.tmu_date.tm_year;
                zfi.tmz_date.tm_mon  = fi.tmu_date.tm_mon;
                zfi.tmz_date.tm_mday = fi.tmu_date.tm_mday;
                zfi.tmz_date.tm_hour = fi.tmu_date.tm_hour;
                zfi.tmz_date.tm_min  = fi.tmu_date.tm_min;
                zfi.tmz_date.tm_sec  = fi.tmu_date.tm_sec;

                zipOpenNewFileInZip(dst, name, &zfi,
                    nullptr, 0, nullptr, 0, nullptr,
                    Z_DEFLATED, Z_DEFAULT_COMPRESSION);
                zipWriteInFileInZip(dst, buf.data(), (unsigned)buf.size());
                zipCloseFileInZip(dst);
            }
            rc = unzGoToNextFile(src);
        }

        // ── Step 2: inject sinf(s) ────────────────────────────────────────────
        if (!sinfs.empty() && !bundleName.empty()) {
            zip_fileinfo zfi = {};
            if (!sinfPaths.empty()) {
                // Manifest-based: zip sinfs with sinfPaths by index
                size_t count = std::min(sinfs.size(), sinfPaths.size());
                for (size_t i = 0; i < count; i++) {
                    std::string sp = "Payload/" + bundleName + ".app/" + sinfPaths[i];
                    zipOpenNewFileInZip(dst, sp.c_str(), &zfi,
                        nullptr, 0, nullptr, 0, nullptr,
                        Z_DEFLATED, Z_DEFAULT_COMPRESSION);
                    zipWriteInFileInZip(dst, sinfs[i].data.data(), (unsigned)sinfs[i].data.size());
                    zipCloseFileInZip(dst);
                }
            } else if (!bundleExecutable.empty()) {
                // Info-based: single sinf to SC_Info/{executable}.sinf
                std::string sp = "Payload/" + bundleName + ".app/SC_Info/"
                               + bundleExecutable + ".sinf";
                zipOpenNewFileInZip(dst, sp.c_str(), &zfi,
                    nullptr, 0, nullptr, 0, nullptr,
                    Z_DEFLATED, Z_DEFAULT_COMPRESSION);
                zipWriteInFileInZip(dst, sinfs[0].data.data(), (unsigned)sinfs[0].data.size());
                zipCloseFileInZip(dst);
            }
        }

        // ── Step 3: write iTunesMetadata.plist from Apple's response metadata ──
        {
            zip_fileinfo zfi = {};
            zipOpenNewFileInZip(dst, "iTunesMetadata.plist", &zfi,
                nullptr, 0, nullptr, 0, nullptr,
                Z_DEFLATED, Z_DEFAULT_COMPRESSION);
            zipWriteInFileInZip(dst, metaBytes.data(), (unsigned)metaBytes.size());
            zipCloseFileInZip(dst);
        }

        // ── Step 4: write iTunesArtwork (PNG, no extension) ──────────────────
        if (!artworkBytes.empty()) {
            zip_fileinfo zfi = {};
            zipOpenNewFileInZip(dst, "iTunesArtwork", &zfi,
                nullptr, 0, nullptr, 0, nullptr,
                Z_DEFLATED, Z_DEFAULT_COMPRESSION);
            zipWriteInFileInZip(dst, artworkBytes.data(), (unsigned)artworkBytes.size());
            zipCloseFileInZip(dst);
        }

        zipClose(dst, nullptr);
        unzClose(src);
    }

    // Extract a string value from a binary or XML plist by key name.
    // Used to read CFBundleExecutable from Info.plist without a full plist parser.
    static std::string extract_plist_string(const std::vector<uint8_t>& data,
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
    static std::vector<std::string> extract_sinf_paths(const std::vector<uint8_t>& data)
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

    static std::string search_url(const std::string& term,
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

    static std::string lookup_url(const std::string& bundleID,
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

    static std::string resolve_destination(const App& app,
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

    static std::string make_filename(const App& app, const std::string& version) {
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

    static int64_t file_size(const std::string& path) {
        std::error_code ec;
        auto sz = fs::file_size(path, ec);
        return ec ? 0 : (int64_t)sz;
    }

    // ── String helpers ────────────────────────────────────────────────────────

    static std::string strip_spaces(const std::string& s) {
        std::string out;
        for (char c : s) if (c != ' ') out += c;
        return out;
    }

    static std::string str_lower(const char* s) {
        std::string out(s);
        for (char& c : out) c = (char)tolower((unsigned char)c);
        return out;
    }
};
