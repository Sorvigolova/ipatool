#pragma once
// HTTP client built on libcurl — Windows + Linux + macOS compatible
//
// Declarations only — see http_client.cpp for implementations.

#include "ipatool.h"
#include <string>
#include <map>
#include <functional>
#include <cstdint>

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
    explicit HttpClient(const std::string& cookieFile = "");
    ~HttpClient();

    // Disable copy
    HttpClient(const HttpClient&)            = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    void set_debug(bool v) { m_debug = v; }

    HttpResponse post(const std::string& url,
                      const std::string& body,
                      const std::map<std::string, std::string>& reqHeaders) const;

    HttpResponse get(const std::string& url,
                     const std::map<std::string, std::string>& reqHeaders = {}) const;

    // Range GET into memory, FOLLOWING redirects (the .ipa download URL may 302,
    // unlike the API endpoints). `rangeSpec` is a curl range string, e.g. "0-0",
    // "100-199", "500-". `maxBytes` (0 = unlimited) caps the buffered body and
    // aborts the transfer if exceeded — a guard in case a host ignores Range and
    // tries to send the whole (potentially multi-GB) file. Returns the 200/206
    // response (body = the bytes; headers include content-range). No retry loop;
    // callers treat any failure as best-effort.
    HttpResponse get_range(const std::string& url,
                           const std::string& rangeSpec,
                           size_t maxBytes = 0,
                           const std::map<std::string, std::string>& reqHeaders = {}) const;

    // Resumable file download with automatic retry.
    // rangeStart==0 means start fresh; >0 resumes from that byte offset.
    // On transient failure each retry continues from where the last left off,
    // using HTTP Range: <offset>- so no already-downloaded bytes are re-fetched.
    void download(const std::string& url,
                  const std::string& destPath,
                  int64_t            rangeStart = 0,
                  std::function<void(int64_t, int64_t)> progress = nullptr) const;

private:
    std::string m_cookieFile;
    bool        m_debug = false;

    // Shared GET/POST implementation with automatic retry on transient errors.
    HttpResponse perform(const std::string& method,
                         const std::string& url,
                         const std::string& body,
                         const std::map<std::string, std::string>& reqHeaders) const;
};
