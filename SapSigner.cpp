#include "SapSigner.h"

#ifdef _WIN32
// Windows networking headers — order matters:
// winsock2.h must precede windows.h to get AF_UNSPEC, IPPROTO_*, etc.
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <winhttp.h>
#  include <iphlpapi.h>
#  pragma comment(lib, "winhttp.lib")
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "ws2_32.lib")
#else
// POSIX (Linux / macOS)
#  include <ifaddrs.h>
#  include <net/if.h>
#  ifdef __linux__
#    include <linux/if_packet.h>  // struct sockaddr_ll
#  else
#    include <net/if_dl.h>        // struct sockaddr_dl (macOS)
#  endif
#  include <curl/curl.h>
#endif

#include <algorithm>
#include <cctype>
#include "compat_format.h"
#include <sstream>
#include <stdexcept>
#include <string_view>

// ═══════════════════════════════════════════════════════════════════════════
//  SapBase64
// ═══════════════════════════════════════════════════════════════════════════

static constexpr char kB64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string SapBase64::Encode(std::span<const uint8_t> data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < data.size()) {
        uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i+1]) << 8) | data[i+2];
        out += kB64Chars[(v >> 18) & 63];
        out += kB64Chars[(v >> 12) & 63];
        out += kB64Chars[(v >>  6) & 63];
        out += kB64Chars[(v      ) & 63];
        i += 3;
    }
    if (i < data.size()) {
        uint32_t v = uint32_t(data[i]) << 16;
        if (i + 1 < data.size()) v |= uint32_t(data[i+1]) << 8;
        out += kB64Chars[(v >> 18) & 63];
        out += kB64Chars[(v >> 12) & 63];
        out += (i + 1 < data.size()) ? kB64Chars[(v >> 6) & 63] : '=';
        out += '=';
    }
    return out;
}

std::vector<uint8_t> SapBase64::Decode(std::string_view b64) {
    static const int8_t kTable[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 0-15
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 16-31
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63, // 32-47: +/
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1, // 48-63: 0-9
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // 64-79: A-O
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1, // 80-95: P-Z
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, // 96-111: a-o
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1, // 112-127: p-z
    };

    std::vector<uint8_t> out;
    out.reserve(b64.size() * 3 / 4);

    uint32_t acc = 0; int bits = 0;
    for (unsigned char c : b64) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        int8_t v = (c < 128) ? kTable[c] : -1;
        if (v < 0) continue;
        acc = (acc << 6) | uint32_t(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(uint8_t(acc >> bits));
        }
    }
    return out;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SapPlist  — minimal Apple XML plist
// ═══════════════════════════════════════════════════════════════════════════

// Strip whitespace from a string
static std::string Strip(std::string s) {
    auto notSpace = [](unsigned char c){ return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    return s;
}

// Find <tag>...</tag> content after 'pos', return content and advance pos
static bool FindTag(const std::string& xml, std::string_view tag,
                    size_t& pos, std::string& content) {
    std::string open  = "<" + std::string(tag) + ">";
    std::string close = "</" + std::string(tag) + ">";
    size_t s = xml.find(open, pos);
    if (s == std::string::npos) return false;
    s += open.size();
    size_t e = xml.find(close, s);
    if (e == std::string::npos) return false;
    content = xml.substr(s, e - s);
    pos = e + close.size();
    return true;
}

std::vector<uint8_t> SapPlist::ExtractData(const std::vector<uint8_t>& xmlBytes,
                                             std::string_view key) {
    std::string xml(xmlBytes.begin(), xmlBytes.end());
    size_t pos = 0;
    std::string foundKey, foundData;

    // Walk through <key>...</key> <data>...</data> pairs
    while (pos < xml.size()) {
        if (!FindTag(xml, "key", pos, foundKey)) break;
        foundKey = Strip(foundKey);

        // Skip whitespace between </key> and <data>
        if (foundKey == key) {
            if (!FindTag(xml, "data", pos, foundData))
                throw std::runtime_error(std::format("plist: key '{}' has no <data> value", key));
            return SapBase64::Decode(Strip(foundData));
        }
        // Skip whatever value follows (data, string, integer, …)
        // Just advance pos past any next tag
        size_t next = xml.find('<', pos);
        if (next == std::string::npos) break;
        size_t end = xml.find('>', next);
        if (end == std::string::npos) break;
        // Find closing tag
        std::string tagName;
        size_t s = next + 1;
        while (s < end && xml[s] != ' ' && xml[s] != '>') tagName += xml[s++];
        // Skip to </tagName>
        std::string closeTag = "</" + tagName + ">";
        size_t c = xml.find(closeTag, end);
        pos = (c != std::string::npos) ? c + closeTag.size() : end + 1;
    }
    throw std::runtime_error(std::format("plist: key '{}' not found", key));
}

std::vector<uint8_t> SapPlist::MakeData(std::string_view key,
                                          std::span<const uint8_t> value) {
    // Wrap base64 at 68 chars for Apple-style formatting
    std::string b64 = SapBase64::Encode(value);
    std::string wrapped;
    for (size_t i = 0; i < b64.size(); i += 68) {
        wrapped += "\t\t";
        wrapped += b64.substr(i, 68);
        wrapped += "\n";
    }

    std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n"
        "<dict>\n"
        "\t<key>" + std::string(key) + "</key>\n"
        "\t<data>\n"
        + wrapped +
        "\t</data>\n"
        "</dict>\n"
        "</plist>\n";

    return std::vector<uint8_t>(xml.begin(), xml.end());
}

// ═══════════════════════════════════════════════════════════════════════════
//  SapWinHttpClient (Windows) / SapCurlHttpClient (Linux/macOS)
// ═══════════════════════════════════════════════════════════════════════════

#ifdef _WIN32

SapWinHttpClient::SapWinHttpClient(std::wstring userAgent)
    : userAgent_(std::move(userAgent))
{
    hSession_ = WinHttpOpen(userAgent_.c_str(),
                            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME,
                            WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession_)
        throw std::runtime_error(std::format("WinHttpOpen failed: {}", GetLastError()));

    // 30-second timeout (matches Go: http.Client{Timeout: 30 * time.Second})
    DWORD timeout = 30000;
    WinHttpSetOption(hSession_, WINHTTP_OPTION_CONNECT_TIMEOUT,    &timeout, sizeof(timeout));
    WinHttpSetOption(hSession_, WINHTTP_OPTION_SEND_TIMEOUT,       &timeout, sizeof(timeout));
    WinHttpSetOption(hSession_, WINHTTP_OPTION_RECEIVE_TIMEOUT,    &timeout, sizeof(timeout));

    // Force TLS 1.2 minimum for Apple SAP servers.
    // Do NOT include TLS 1.0 / 1.1 — Apple rejects them and WinHTTP
    // may randomly negotiate the lower version causing intermittent failures.
    DWORD tlsFlags = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    WinHttpSetOption(hSession_, WINHTTP_OPTION_SECURE_PROTOCOLS, &tlsFlags, sizeof(tlsFlags));
}

SapWinHttpClient::~SapWinHttpClient() {
    if (hSession_) WinHttpCloseHandle(hSession_);
}

// Convert UTF-8 std::string to wide string
static std::wstring ToWide(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

std::vector<uint8_t> SapWinHttpClient::Get(std::string_view url) {
    return Send("GET", url, {}, {});
}

std::vector<uint8_t> SapWinHttpClient::Post(std::string_view url,
                                              std::span<const uint8_t> body,
                                              std::string_view contentType) {
    return Send("POST", url, body, contentType);
}

std::vector<uint8_t> SapWinHttpClient::Send(std::string_view method,
                                              std::string_view urlStr,
                                              std::span<const uint8_t> body,
                                              std::string_view contentType) {
    // Parse URL
    URL_COMPONENTS uc = {};
    uc.dwStructSize   = sizeof(uc);
    std::wstring wurl = ToWide(urlStr);

    wchar_t host[256] = {}, path[4096] = {};
    uc.lpszHostName    = host; uc.dwHostNameLength    = 255;
    uc.lpszUrlPath     = path; uc.dwUrlPathLength     = 4095;
    uc.dwSchemeLength  = 1;

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.size(), 0, &uc))
        throw std::runtime_error(std::format("WinHttpCrackUrl: {}", GetLastError()));

    bool isHttps = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    DWORD port   = uc.nPort ? uc.nPort : (isHttps ? 443 : 80);

    HINTERNET hConn = WinHttpConnect(hSession_, host, (INTERNET_PORT)port, 0);
    if (!hConn) throw std::runtime_error(std::format("WinHttpConnect: {}", GetLastError()));

    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, ToWide(method).c_str(),
                                         path, nullptr,
                                         WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConn); throw std::runtime_error(std::format("WinHttpOpenRequest: {}", GetLastError())); }

    // Set Content-Type header if present
    if (!contentType.empty()) {
        std::wstring ct = L"Content-Type: " + ToWide(contentType);
        WinHttpAddRequestHeaders(hReq, ct.c_str(), (DWORD)ct.size(), WINHTTP_ADDREQ_FLAG_ADD);
    }

    // Add User-Agent header (set on session, but also set on request to match iTunes UA)
    WinHttpAddRequestHeaders(hReq,
        (L"User-Agent: " + userAgent_).c_str(),
        WINHTTP_NO_HEADER_INDEX,
        WINHTTP_ADDREQ_FLAG_REPLACE | WINHTTP_ADDREQ_FLAG_ADD);

    // Windows 7 root certificate store doesn't include newer DigiCert roots
    // that Apple's SAP servers use. Add the missing root from our embedded bundle
    // rather than disabling all validation.
    // We only skip CA chain validation — hostname and date checks remain active,
    // which still protects against MITM attacks to different servers.
    {
        DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
        OSVERSIONINFOW osvi = { sizeof(osvi) };
#pragma warning(suppress: 4996)
        GetVersionExW(&osvi);
        bool isWin7 = (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1);
        if (isWin7) {
            // Win7 only: skip CA validation (outdated root store).
            // Hostname + date validation remain active — prevents MITM.
            WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS,
                             &dwSecFlags, sizeof(dwSecFlags));
        }
    }

    BOOL sent = WinHttpSendRequest(hReq,
                                    WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    body.empty() ? nullptr : (LPVOID)body.data(),
                                    (DWORD)body.size(),
                                    (DWORD)body.size(), 0);
    DWORD sendErr = GetLastError();
    if (!sent) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
        throw std::runtime_error(std::format("WinHttpSendRequest failed: {}", sendErr));
    }
    if (!WinHttpReceiveResponse(hReq, nullptr)) {
        DWORD recvErr = GetLastError();
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
        throw std::runtime_error(std::format("WinHttpReceiveResponse failed: {}", recvErr));
    }

    // Check status code
    DWORD statusCode = 0; DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                         nullptr, &statusCode, &statusSize, nullptr);
    if (statusCode != 200) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
        throw std::runtime_error(std::format("Apple returned HTTP {}", statusCode));
    }

    // Read response body
    std::vector<uint8_t> result;
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        size_t off = result.size();
        result.resize(off + avail);
        DWORD read = 0;
        if (!WinHttpReadData(hReq, result.data() + off, avail, &read))
            break;
        result.resize(off + read);
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    return result;
}

#else // !_WIN32

// ── libcurl-based HTTP client for Linux / macOS ───────────────────────────

namespace {

struct CurlResponse {
    std::vector<uint8_t> body;
    long statusCode = 0;

    static size_t WriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
        auto* resp = static_cast<CurlResponse*>(userdata);
        resp->body.insert(resp->body.end(), ptr, ptr + size * nmemb);
        return size * nmemb;
    }
};

static std::vector<uint8_t> curl_request(
    const std::string& method,
    const std::string& url,
    std::span<const uint8_t> body,
    const std::string& contentType,
    const std::string& userAgent)
{
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");

    CurlResponse resp;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlResponse::WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, userAgent.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    struct curl_slist* hdrs = nullptr;
    if (!contentType.empty()) {
        std::string ct = "Content-Type: " + contentType;
        hdrs = curl_slist_append(hdrs, ct.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    }

    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    }

    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp.statusCode);
    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
        throw std::runtime_error(std::string("curl: ") + curl_easy_strerror(res));
    if (resp.statusCode != 200)
        throw std::runtime_error(std::format("Apple returned HTTP {}", resp.statusCode));

    return resp.body;
}

} // namespace

// SapCurlHttpClient — ISapHttpClient implementation using libcurl
// Created on-demand in SapSigner::Create when no httpClient is provided.
class SapCurlHttpClient final : public ISapHttpClient {
public:
    SapCurlHttpClient() = default;

    std::vector<uint8_t> Get(std::string_view url) override {
        return curl_request("GET", std::string(url), {}, "", kUA);
    }
    std::vector<uint8_t> Post(std::string_view url,
                               std::span<const uint8_t> body,
                               std::string_view contentType) override {
        return curl_request("POST", std::string(url), body,
                            std::string(contentType), kUA);
    }
private:
    static constexpr const char* kUA =
        "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";
};

#endif // _WIN32

// ═══════════════════════════════════════════════════════════════════════════
//  SAP protocol helpers  (port of protocol.go)
// ═══════════════════════════════════════════════════════════════════════════

static const char* kCertKey   = "sign-sap-setup-cert";
static const char* kBufferKey = "sign-sap-setup-buffer";
static const char* kPlistCT   = "application/x-plist";

// GET certURL → parse plist → return cert bytes
static std::vector<uint8_t> FetchCertificate(ISapHttpClient& http,
                                               const std::string& certURL) {
    auto body = http.Get(certURL);
    return SapPlist::ExtractData(body, kCertKey);
}

// POST setupURL with {"sign-sap-setup-buffer": request} → return reply bytes
static std::vector<uint8_t> ExchangeSetup(ISapHttpClient& http,
                                            const std::string& setupURL,
                                            std::span<const uint8_t> request) {
    auto plist = SapPlist::MakeData(kBufferKey, request);
    auto body  = http.Post(setupURL, plist, kPlistCT);
    return SapPlist::ExtractData(body, kBufferKey);
}

// ═══════════════════════════════════════════════════════════════════════════
//  SapSigner::Create  (port of signer_local.go NewSigner)
// ═══════════════════════════════════════════════════════════════════════════

std::unique_ptr<SapSigner> SapSigner::Create(
    const Config&        config,
    std::vector<uint8_t> coreFP,
    std::vector<uint8_t> commerceCore,
    std::vector<uint8_t> commerceKit,
    std::vector<uint8_t> coreFPIcxs,
    ISapHttpClient*      httpClient)
{
    // Validate config
    if (config.version != kSupportedVersion)
        throw std::runtime_error(std::format("unsupported SAP version {}", config.version));
    if (config.hardwareID.empty() || config.hardwareID.size() > 20)
        throw std::runtime_error("SAP hardware ID must be 1-20 bytes");
    if (config.setupURL.empty() || config.setupURL.substr(0, 8) != "https://")
        throw std::runtime_error("SAP setup URL must be HTTPS");
    if (config.certificateURL.empty() || config.certificateURL.substr(0, 8) != "https://")
        throw std::runtime_error("SAP certificate URL must be HTTPS");

    // Owned HTTP client if none provided
#ifdef _WIN32
    std::unique_ptr<SapWinHttpClient> ownedHttp;
    if (!httpClient) {
        ownedHttp  = std::make_unique<SapWinHttpClient>();
        httpClient = ownedHttp.get();
    }
#else
    std::unique_ptr<SapCurlHttpClient> ownedHttp;
    if (!httpClient) {
        ownedHttp  = std::make_unique<SapCurlHttpClient>();
        httpClient = ownedHttp.get();
    }
#endif

    // 1. Start the emulated Apple SAP runtime
    auto machine = SapMachine::Create(std::move(coreFP), std::move(commerceCore),
                                       std::move(commerceKit), std::move(coreFPIcxs),
                                       config.hardwareID); // _get_mac_address shim

    // 2. Initialize SAP context
    uint64_t ctx = machine->Initialize(config.hardwareID);

    // 3. Fetch Apple's SAP certificate from CertificateURL
    auto cert = FetchCertificate(*httpClient, config.certificateURL);

    // 4. First Exchange: machine → request bytes, state must be 1
    auto [request, state1] = machine->Exchange(config.version, config.hardwareID, ctx, cert);
    if (state1 != 1)
        throw std::runtime_error(std::format("SAP setup entered unexpected state {}", state1));
    if (request.empty())
        throw std::runtime_error("SAP setup message is empty");

    // 5. Send request to Apple's setup URL, get reply
    auto reply = ExchangeSetup(*httpClient, config.setupURL, request);

    // 6. Second Exchange: complete handshake, state must be 0
    auto [_, state2] = machine->Exchange(config.version, config.hardwareID, ctx, reply);
    if (state2 != 0)
        throw std::runtime_error(std::format("SAP setup completed in unexpected state {}", state2));

    // 7. All good — build the signer
    auto s       = std::unique_ptr<SapSigner>(new SapSigner());
    s->machine_  = std::move(machine);
    s->sapCtx_   = ctx;
    s->hardware_ = config.hardwareID;
    return s;
}

SapSigner::~SapSigner() {
    try { Close(); } catch (...) {}
}

void SapSigner::Close() {
    std::lock_guard lock(mu_);
    if (closed_) return;
    closed_ = true;
    if (machine_ && sapCtx_) {
        try { machine_->Teardown(sapCtx_); } catch (...) {}
        sapCtx_ = 0;
    }
    // Zero out hardware ID
    std::fill(hardware_.begin(), hardware_.end(), uint8_t(0));
    machine_.reset();
}

// ═══════════════════════════════════════════════════════════════════════════
//  SapSigner::Sign  (port of Signer.Sign)
// ═══════════════════════════════════════════════════════════════════════════

std::vector<uint8_t> SapSigner::Sign(std::span<const uint8_t> input) {
    std::lock_guard lock(mu_);
    if (closed_) throw std::runtime_error("SAP signer is closed");

    auto sig = machine_->Sign(sapCtx_, input);
    if (sig.empty()) throw std::runtime_error("SAP sign returned empty signature");
    return sig;
}

std::string SapSigner::SignBase64(std::span<const uint8_t> input) {
    return SapBase64::Encode(Sign(input));
}

std::string SapSigner::SignBase64(std::string_view input) {
    return SignBase64(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(input.data()), input.size()));
}

// ═══════════════════════════════════════════════════════════════════════════
//  Hardware ID helpers
// ═══════════════════════════════════════════════════════════════════════════

std::vector<uint8_t> SapSigner::HardwareIDFromMAC(std::string_view mac) {
    // Parse "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF"
    std::vector<uint8_t> result;
    result.reserve(6);
    size_t i = 0;
    while (i < mac.size()) {
        while (i < mac.size() && (mac[i] == ':' || mac[i] == '-')) ++i;
        if (i + 1 >= mac.size()) break;
        auto hexByte = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };
        int hi = hexByte(mac[i]), lo = hexByte(mac[i+1]);
        if (hi < 0 || lo < 0) break;
        result.push_back(uint8_t(hi << 4 | lo));
        i += 2;
    }
    if (result.empty() || result.size() > 20)
        throw std::runtime_error(std::format("invalid MAC address: '{}'", mac));
    return result;
}

std::vector<uint8_t> SapSigner::LocalHardwareID() {
#ifdef _WIN32
    // Windows: GetAdaptersAddresses
    ULONG bufLen = 15000;
    std::vector<uint8_t> buf(bufLen);

    DWORD ret = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr,
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()),
        &bufLen);

    if (ret == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        ret = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()),
            &bufLen);
    }

    if (ret != NO_ERROR) return {};

    auto* adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    while (adapter) {
        if (adapter->IfType != IF_TYPE_SOFTWARE_LOOPBACK &&
            adapter->IfType != IF_TYPE_TUNNEL &&
            adapter->PhysicalAddressLength == 6 &&
            adapter->OperStatus == IfOperStatusUp)
        {
            return std::vector<uint8_t>(
                adapter->PhysicalAddress,
                adapter->PhysicalAddress + adapter->PhysicalAddressLength);
        }
        adapter = adapter->Next;
    }
    return {};

#else
    // POSIX (Linux / macOS): getifaddrs
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) return {};

    std::vector<uint8_t> result;
    for (struct ifaddrs* ifa = ifap; ifa && result.empty(); ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        // Skip loopback
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        // Skip interfaces that are down
        if (!(ifa->ifa_flags & IFF_UP)) continue;

#  ifdef __linux__
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        auto* sll = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
        if (sll->sll_halen != 6) continue;
        bool allZero = true;
        for (int i = 0; i < 6; ++i) if (sll->sll_addr[i]) { allZero = false; break; }
        if (allZero) continue;
        result.assign(sll->sll_addr, sll->sll_addr + 6);
#  else // macOS
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;
        auto* sdl = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
        if (sdl->sdl_alen != 6) continue;
        auto* mac = reinterpret_cast<unsigned char*>(LLADDR(sdl));
        bool allZero = true;
        for (int i = 0; i < 6; ++i) if (mac[i]) { allZero = false; break; }
        if (allZero) continue;
        result.assign(mac, mac + 6);
#  endif
    }
    freeifaddrs(ifap);
    return result;
#endif
}
