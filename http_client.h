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
