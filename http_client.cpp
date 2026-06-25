#include "http_client.h"
#include <curl/curl.h>
#include <stdexcept>
#include <cctype>
#include <cstdio>

// ─────────────────────────────────────────────────────────────────────────────
// Apple GSA CA bundle — Root CA + Server Authentication CA
// Embedded so ipatool works standalone without the Windows cert store.
// These are Apple's *public* CA certificates, freely available from
// https://www.apple.com/certificateauthority/
//
// Pass to libcurl via CURLOPT_CAINFO_BLOB (curl 7.77+).
//
// Kept as a static local table in this .cpp, same style as appstore.cpp's
// storefront_map() — data that's only needed inside this file shouldn't
// leak into the header.
// ─────────────────────────────────────────────────────────────────────────────

static const char APPLE_GSA_CA_BUNDLE[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET\n"
    "MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv\n"
    "biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0\n"
    "MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw\n"
    "bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx\n"
    "FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n"
    "ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+\n"
    "+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1\n"
    "XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w\n"
    "tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW\n"
    "q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM\n"
    "aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E\n"
    "BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3\n"
    "R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE\n"
    "ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93\n"
    "d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl\n"
    "IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0\n"
    "YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj\n"
    "b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp\n"
    "Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc\n"
    "NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP\n"
    "y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7\n"
    "R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg\n"
    "xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP\n"
    "IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX\n"
    "UKqK1drk/NAJBzewdXUh\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIID+DCCAuCgAwIBAgIII2l0BK3LgxQwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UE\n"
    "BhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRp\n"
    "ZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTE0\n"
    "MDMwODAxNTMwNFoXDTI5MDMwODAxNTMwNFowbTEnMCUGA1UEAwweQXBwbGUgU2Vy\n"
    "dmVyIEF1dGhlbnRpY2F0aW9uIENBMSAwHgYDVQQLDBdDZXJ0aWZpY2F0aW9uIEF1\n"
    "dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwggEiMA0G\n"
    "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5Jhawy4ercRWSjt+qPuGA11O6pGDM\n"
    "fIVy9zB8CU9XDUr/4V7JS1ATAmSxvTk10dcEUcEY+iL6rt+YGNa/Tk1DEPoliJ/T\n"
    "QIV25SKBtlRFc5qL45xIGoZ6w1Hi2pX4pH3bMN5sDsTF9WyY56b6VyAdGXN6Ds1j\n"
    "D7cniC7hmmiCuEBsYxYkZivnsuJUfeeIOaIbgT4C0znYl3dKMgzWCgqzBJvxcm9j\n"
    "qBUebDfoD9tTkNYpXLxqV5tGeAo+JOqaP6HYP/XbbqhsgrXdmTjsklaUpsVzJtGu\n"
    "CLLGUueOdkuJuFQPbuDZQtsqZYdGFLuWuFe7UeaEE/cNobaJrHzRIXSrAgMBAAGj\n"
    "gaYwgaMwHQYDVR0OBBYEFCzFbVLdMe+M7AiB7d/cykMARQHQMA8GA1UdEwEB/wQF\n"
    "MAMBAf8wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wLgYDVR0fBCcw\n"
    "JTAjoCGgH4YdaHR0cDovL2NybC5hcHBsZS5jb20vcm9vdC5jcmwwDgYDVR0PAQH/\n"
    "BAQDAgEGMBAGCiqGSIb3Y2QGAgwEAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQAj8QZ+\n"
    "UEGBol7TcKRJka/YzGeMoSV9xJqTOS/YafsbQVtE19lryzslCRry9OPHnOiwW/Df\n"
    "3SIlERWTuUle2gxmel7Xb/Bj1GWMxHpUfVZPZZr92sSyyLC4oct94EeoQBW4Fhnt\n"
    "W2GO36rQzdI6wH46nyJO39/0ThrNk//Q8EVVZDM+1OXaaKATinYwJ9S/+B529vnD\n"
    "AO+xg+pTbVw1xw0HAbr4Ybn+xZprQ2GBA+u6X3Cd6G+UJEvczpKoLqI1PONJ4BZ3\n"
    "otxruY0YQrk2lkMyxst2mTU22FbGmF3Db6V+lcLVegoCIGZ4kvJnpCMN6Am9zCEx\n"
    "EKC9vrXdTN1GA5mZ\n"
    "-----END CERTIFICATE-----\n";

static const size_t APPLE_GSA_CA_BUNDLE_LEN = sizeof(APPLE_GSA_CA_BUNDLE) - 1;

// ─────────────────────────────────────────────────────────────────────────────
// curl callbacks
// ─────────────────────────────────────────────────────────────────────────────

static size_t body_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* buf = reinterpret_cast<std::string*>(userdata);
    buf->append(ptr, size * nmemb);
    return size * nmemb;
}

struct DownloadState {
    FILE*    fp        = nullptr;
    int64_t  rangeStart= 0;
    int64_t  received  = 0;
    int64_t  total     = 0;
    std::function<void(int64_t,int64_t)> progress;
};

static size_t file_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto*  ds      = reinterpret_cast<DownloadState*>(userdata);
    size_t written = fwrite(ptr, size, nmemb, ds->fp);
    ds->received  += static_cast<int64_t>(written * size);
    if (ds->progress) ds->progress(ds->rangeStart + ds->received, ds->total);
    return written * size;
}

static int xferinfo_cb(void* userdata,
                       curl_off_t dltotal, curl_off_t dlnow,
                       curl_off_t, curl_off_t) {
    auto* ds = reinterpret_cast<DownloadState*>(userdata);
    if (dltotal > 0)
        ds->total = ds->rangeStart + static_cast<int64_t>(dltotal);
    return 0;
}

static size_t header_cb(char* buffer, size_t size, size_t nitems, void* userdata) {
    auto* hdrs = reinterpret_cast<std::map<std::string,std::string>*>(userdata);
    std::string line(buffer, size * nitems);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string key   = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        while (!value.empty() && value.front() == ' ') value.erase(value.begin());
        while (!value.empty() && (value.back()=='\r'||value.back()=='\n'))
            value.pop_back();
        for (char& c : key) c = static_cast<char>(tolower((unsigned char)c));
        (*hdrs)[key] = value;
    }
    return size * nitems;
}

// Store/download User-Agent — platform-dependent to match anisette profile.
#if defined(_WIN32) || defined(_WIN64)
static constexpr const char* USER_AGENT =
    "Configurator/2.15 (Macintosh; OS X 11.0.0; 16G29) AppleWebKit/2603.3.8";
#else
static constexpr const char* USER_AGENT =
    "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";
#endif

// ─────────────────────────────────────────────────────────────────────────────
// HttpClient
// ─────────────────────────────────────────────────────────────────────────────

HttpClient::HttpClient(const std::string& cookieFile)
    : m_cookieFile(cookieFile)
{ curl_global_init(CURL_GLOBAL_ALL); }

HttpClient::~HttpClient() { curl_global_cleanup(); }

HttpResponse HttpClient::post(const std::string& url,
                  const std::string& body,
                  const std::map<std::string,std::string>& reqHeaders) const
{ return perform("POST", url, body, reqHeaders); }

HttpResponse HttpClient::get(const std::string& url,
                 const std::map<std::string,std::string>& reqHeaders) const
{ return perform("GET", url, "", reqHeaders); }

void HttpClient::download(const std::string& url,
              const std::string& destPath,
              int64_t            rangeStart,
              std::function<void(int64_t,int64_t)> progress) const
{
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");

    const char* mode = (rangeStart > 0) ? "ab" : "wb";
    FILE* fp = fopen(destPath.c_str(), mode);
    if (!fp) { curl_easy_cleanup(curl);
               throw std::runtime_error("failed to open: " + destPath); }

    DownloadState ds;
    ds.fp         = fp;
    ds.rangeStart = rangeStart;
    ds.progress   = progress;

    curl_easy_setopt(curl, CURLOPT_URL,              url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT,        USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,   1L);
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS,      (long)CURLSSLOPT_NATIVE_CA);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,   15L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,    file_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,        &ds);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS,       0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xferinfo_cb);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA,     &ds);
    if (rangeStart > 0) {
        std::string range = std::to_string(rangeStart) + "-";
        curl_easy_setopt(curl, CURLOPT_RANGE, range.c_str());
    }
    if (!m_cookieFile.empty()) {
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, m_cookieFile.c_str());
        curl_easy_setopt(curl, CURLOPT_COOKIEJAR,  m_cookieFile.c_str());
    }
    CURLcode rc = curl_easy_perform(curl);
    fclose(fp);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK)
        throw std::runtime_error(std::string("HTTP request failed: ")
                                 + curl_easy_strerror(rc));
}

HttpResponse HttpClient::perform(const std::string& method,
                     const std::string& url,
                     const std::string& body,
                     const std::map<std::string,std::string>& reqHeaders) const
{
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");

    HttpResponse resp;
    std::string  respBody;

    curl_easy_setopt(curl, CURLOPT_URL,             url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT,       USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,  15L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,         30L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   body_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,       &respBody);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION,  header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA,      &resp.headers);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,  0L);

    // ── Per-host SSL policy ───────────────────────────────────────────────
    if (url.find("gsa.apple.com") != std::string::npos) {
        static const struct curl_blob apple_blob {
            const_cast<char*>(APPLE_GSA_CA_BUNDLE),
            APPLE_GSA_CA_BUNDLE_LEN,
            CURL_BLOB_NOCOPY
        };
        curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &apple_blob);
    }

    if (!m_cookieFile.empty()) {
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, m_cookieFile.c_str());
        curl_easy_setopt(curl, CURLOPT_COOKIEJAR,  m_cookieFile.c_str());
    } else {
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
    }

    struct curl_slist* hdrs = nullptr;
    for (auto& [k,v] : reqHeaders) {
        std::string h = k + ": " + v;
        hdrs = curl_slist_append(hdrs, h.c_str());
    }
    if (hdrs) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST,          1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    } else {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    }

    // Direct connection — no proxy
    CURLcode rc = curl_easy_perform(curl);
    if (hdrs) curl_slist_free_all(hdrs);

    if (rc != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error(std::string("HTTP request failed: ")
                                 + curl_easy_strerror(rc));
    }

    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    resp.statusCode = static_cast<int>(code);
    resp.body       = std::move(respBody);
    curl_easy_cleanup(curl);
    return resp;
}
