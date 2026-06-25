#pragma once
// HTTP client built on libcurl.
// SSL backend: Schannel (Windows) — native, fast, no OpenSSL dependency for HTTPS.
// OpenSSL is still used separately by gsa.cpp for SRP/HMAC/AES crypto operations.
//
// Declarations only — see http_client.cpp for implementations.

#include "ipatool.h"
#include <string>
#include <map>
#include <functional>
#include <cstdint>

// ── HttpResponse ─────────────────────────────────────────────────────────────

struct HttpResponse {
    int         statusCode = 0;
    std::string body;
    std::map<std::string,std::string> headers;
};

// ── HttpClient ────────────────────────────────────────────────────────────────

class HttpClient {
public:
    explicit HttpClient(const std::string& cookieFile = "");
    ~HttpClient();

    HttpClient(const HttpClient&)            = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    HttpResponse post(const std::string& url,
                      const std::string& body,
                      const std::map<std::string,std::string>& reqHeaders) const;

    HttpResponse get(const std::string& url,
                     const std::map<std::string,std::string>& reqHeaders = {}) const;

    void download(const std::string& url,
                  const std::string& destPath,
                  int64_t            rangeStart = 0,
                  std::function<void(int64_t,int64_t)> progress = nullptr) const;

    const std::string& cookie_file() const { return m_cookieFile; }

private:
    std::string m_cookieFile;

    HttpResponse perform(const std::string& method,
                         const std::string& url,
                         const std::string& body,
                         const std::map<std::string,std::string>& reqHeaders) const;
};
