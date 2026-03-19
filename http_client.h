#pragma once
// HTTP client built on libcurl — Windows + Linux + macOS compatible

#include "ipatool.h"
#include <string>
#include <map>
#include <vector>
#include <functional>
#include <stdexcept>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <curl/curl.h>

namespace fs = std::filesystem;

// ── Write callbacks ───────────────────────────────────────────────────────────

static size_t body_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* buf = reinterpret_cast<std::string*>(userdata);
    buf->append(ptr, size * nmemb);
    return size * nmemb;
}

struct DownloadState {
    FILE*    fp        = nullptr;
    int64_t  total     = 0;
    int64_t  received  = 0;
    int64_t  rangeStart = 0;  // bytes already on disk before this session
    std::function<void(int64_t, int64_t)> progress;
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
                       curl_off_t /*ultotal*/, curl_off_t /*ulnow*/) {
    auto* ds = reinterpret_cast<DownloadState*>(userdata);
    if (dltotal > 0)
        ds->total = ds->rangeStart + static_cast<int64_t>(dltotal);
    return 0; // return non-zero to abort
}

static size_t header_cb(char* buffer, size_t size, size_t nitems, void* userdata) {
    auto* hdrs = reinterpret_cast<std::map<std::string, std::string>*>(userdata);
    std::string line(buffer, size * nitems);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string key   = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ')) value.erase(value.begin());
        while (!value.empty() && (value.back() == '\r' || value.back() == '\n'))
            value.pop_back();
        // lower-case key for portable lookup
        for (char& c : key) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        (*hdrs)[key] = value;
    }
    return size * nitems;
}

// ── HttpResponse ──────────────────────────────────────────────────────────────

struct HttpResponse {
    int         statusCode = 0;
    std::string body;
    std::map<std::string, std::string> headers;
};

// ── HttpClient ────────────────────────────────────────────────────────────────

class HttpClient {
public:
    // cookieFile: path to persist cookies between runs (empty = in-memory only)
    explicit HttpClient(const std::string& cookieFile = "")
        : m_cookieFile(cookieFile)
    {
        curl_global_init(CURL_GLOBAL_ALL);
    }
    ~HttpClient() { curl_global_cleanup(); }

    // Disable copy
    HttpClient(const HttpClient&)            = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    HttpResponse post(const std::string& url,
                      const std::string& body,
                      const std::map<std::string, std::string>& reqHeaders) const
    {
        return perform("POST", url, body, reqHeaders);
    }

    HttpResponse get(const std::string& url,
                     const std::map<std::string, std::string>& reqHeaders = {}) const
    {
        return perform("GET", url, "", reqHeaders);
    }

    // Resumable file download. rangeStart==0 means start fresh.
    void download(const std::string& url,
                  const std::string& destPath,
                  int64_t            rangeStart = 0,
                  std::function<void(int64_t, int64_t)> progress = nullptr) const
    {
        CURL* curl = curl_easy_init();
        if (!curl) throw std::runtime_error("curl_easy_init failed");

        // Use "ab" (append binary) when resuming, "wb" otherwise.
        // On Windows fopen works fine for binary files.
        const char* openMode = (rangeStart > 0) ? "ab" : "wb";
        FILE* fp = fopen(destPath.c_str(), openMode);
        if (!fp) {
            curl_easy_cleanup(curl);
            throw std::runtime_error("failed to open file: " + destPath);
        }

        DownloadState ds;
        ds.fp         = fp;
        ds.progress   = progress;
        ds.rangeStart = rangeStart;

        std::map<std::string, std::string> respHeaders;

        curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
        curl_easy_setopt(curl, CURLOPT_USERAGENT,      USER_AGENT);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);   // 15s to connect
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024L); // abort if < 1 KB/s
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,  30L);  // for more than 30s
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,      file_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,          &ds);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,   xferinfo_cb);
        curl_easy_setopt(curl, CURLOPT_XFERINFODATA,       &ds);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS,         0L);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA,     &respHeaders);
        if (!m_cookieFile.empty()) {
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, m_cookieFile.c_str());
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR,  m_cookieFile.c_str());
        } else {
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
        }

        if (rangeStart > 0) {
            std::string range = std::to_string(rangeStart) + "-";
            curl_easy_setopt(curl, CURLOPT_RANGE, range.c_str());
        }

        CURLcode rc = curl_easy_perform(curl);
        fclose(fp);
        curl_easy_cleanup(curl);

        if (rc != CURLE_OK)
            throw std::runtime_error(
                curl_easy_strerror(rc));
    }

private:
    static constexpr const char* USER_AGENT =
        "Configurator/2.15 (Macintosh; OS X 11.0.0; 16G29) AppleWebKit/2603.3.8";

    std::string m_cookieFile;

    HttpResponse perform(const std::string& method,
                         const std::string& url,
                         const std::string& body,
                         const std::map<std::string, std::string>& reqHeaders) const
    {
        CURL* curl = curl_easy_init();
        if (!curl) throw std::runtime_error("curl_easy_init failed");

        HttpResponse resp;
        std::string  respBody;

        curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
        curl_easy_setopt(curl, CURLOPT_USERAGENT,      USER_AGENT);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);  // 15s to establish connection
        curl_easy_setopt(curl, CURLOPT_TIMEOUT,        30L);  // 30s total for API calls
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  body_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &respBody);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA,     &resp.headers);
        // Don't follow redirects automatically — we handle them manually
        // (mirrors the Go http.ErrUseLastResponse logic)
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        // Cookie engine: load from file and save back after each request
        if (!m_cookieFile.empty()) {
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, m_cookieFile.c_str());
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR,  m_cookieFile.c_str());
        } else {
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, ""); // enable in-memory cookie engine
        }

        // Build header list
        struct curl_slist* hdrs = nullptr;
        for (auto& [k, v] : reqHeaders) {
            std::string h = k + ": " + v;
            hdrs = curl_slist_append(hdrs, h.c_str());
        }
        if (hdrs) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

        if (method == "POST") {
            curl_easy_setopt(curl, CURLOPT_POST,          1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    body.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                             static_cast<long>(body.size()));
        } else {
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        }

        CURLcode rc = curl_easy_perform(curl);
        if (hdrs) curl_slist_free_all(hdrs);

        if (rc != CURLE_OK) {
            curl_easy_cleanup(curl);
            throw std::runtime_error(
                std::string("HTTP request failed: ") + curl_easy_strerror(rc));
        }

        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        resp.statusCode = static_cast<int>(code);
        resp.body       = std::move(respBody);

        curl_easy_cleanup(curl);
        return resp;
    }
};
