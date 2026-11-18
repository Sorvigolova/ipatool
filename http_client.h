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

    // Optional hook called with every completed API response (post/get).
    // Used by the Store AMD flow to report x-apple-amd-* headers under --debug.
    using Observer = std::function<void(const std::string& method,
                                        const std::string& url,
                                        const HttpResponse& res)>;
    void set_observer(Observer cb) { m_observer = std::move(cb); }

    // Drop every stored cookie by removing the cookie file. Cookie state lives
    // only in that file (each request reloads it), so this starts the next
    // request with an empty jar. Called at the start of a login so a stale
    // session cookie can't ride along into a fresh sign-in.
    void clear_cookies() const;

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

    // Per-chunk integrity check used by the chunk-queue path: called with a
    // chunk's index and its freshly downloaded bytes; return false if they don't
    // match the expected hash, which makes the worker re-fetch that chunk. Keeps
    // the hash format (and any crypto dependency) in the caller.
    using ChunkVerifier = std::function<bool(int chunkIndex, const uint8_t* data, size_t len)>;

    // Fetch a large file over several connections at once, writing the finished
    // bytes to destPath. Returns true on success; false means the caller should
    // fall back to the single-connection download() (same destPath). Declines
    // (returns false, nothing left at destPath) for a small file, a server that
    // won't honour ranges, or a resumable partial already on disk.
    //
    // With chunkSize/chunkCount from the store's download manifest it uses a
    // chunk-queue: 4 workers pull free chunk indices off a shared counter, fetch
    // each chunk's range, md5-check it via verifyChunk and re-fetch a bad chunk in
    // place — load-balancing across workers and verifying as it goes. Without a
    // manifest it splits the file into 4 equal contiguous parts (and then needs a
    // strong ETag as the only cross-connection consistency guard). Staging is
    // unique to this process, so concurrent ipatool runs never share temp files.
    bool download_parallel(const std::string& url,
                           const std::string& destPath,
                           std::function<void(int64_t, int64_t)> progress = nullptr,
                           int64_t       chunkSize   = 0,
                           int           chunkCount  = 0,
                           ChunkVerifier verifyChunk = nullptr) const;

    // Fetch bytes [start,end] inclusive into `out` (cleared first), for targeted
    // repair of a single corrupt chunk (the store ships per-chunk md5s in the
    // download response). Transport/timeout failures are retried a few times; a
    // non-206 response or a wrong byte count is a hard failure (false, no retry)
    // so the caller can fall back to a full re-download.
    bool download_range(const std::string& url,
                        int64_t start, int64_t end,
                        std::string& out) const;

private:
    std::string m_cookieFile;
    bool        m_debug = false;
    Observer    m_observer;

    // Shared GET/POST implementation with automatic retry on transient errors.
    HttpResponse perform(const std::string& method,
                         const std::string& url,
                         const std::string& body,
                         const std::map<std::string, std::string>& reqHeaders) const;
};
