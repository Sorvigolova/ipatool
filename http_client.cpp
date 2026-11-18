#include "http_client.h"
#include "path_utf8.h"   // ipt::fopen_utf8 / ipt::fs_path — Unicode paths on Windows
#include <curl/curl.h>
#include <stdexcept>
#include <cctype>
#include <cstdio>
#include <thread>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <atomic>
#include <random>
#include <vector>
#if defined(_WIN32)
#  include <process.h>   // _getpid
#  include <io.h>        // _isatty, _fileno
#else
#  include <unistd.h>    // getpid, isatty
#endif

// ── Write callbacks ───────────────────────────────────────────────────────────

static size_t body_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* buf = reinterpret_cast<std::string*>(userdata);
    buf->append(ptr, size * nmemb);
    return size * nmemb;
}

// Capped body sink for get_range: appends to `buf` but aborts (returns a short
// count → CURLE_WRITE_ERROR) once `cap` bytes would be exceeded. cap==0 means
// no limit.
struct CappedBuf { std::string* buf; size_t cap; };
static size_t capped_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto*  cb = reinterpret_cast<CappedBuf*>(userdata);
    size_t n  = size * nmemb;
    if (cb->cap && cb->buf->size() + n > cb->cap) return 0;  // over cap → abort
    cb->buf->append(ptr, n);
    return n;
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
                       curl_off_t dltotal, curl_off_t /*dlnow*/,
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

// ── Cookie persistence ────────────────────────────────────────────────────────
// Cookies are read from / written to the file here instead of via
// CURLOPT_COOKIEFILE / CURLOPT_COOKIEJAR. Those take a char* path whose
// encoding depends on how libcurl was built, so on Windows profiles with
// non-ASCII names (C:\Users\Анар) and no 8.3 short names the jar silently
// failed to open. The file keeps the Netscape format libcurl used.

// Enable the cookie engine and feed it the lines stored in `file`.
static void load_cookies(CURL* curl, const std::string& file) {
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");   // engine on, no file
    if (file.empty()) return;

    std::ifstream in(ipt::fs_path(file), std::ios::binary);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        // "#HttpOnly_" lines are cookies; other '#' lines are comments.
        if (line[0] == '#' && line.rfind("#HttpOnly_", 0) != 0) continue;
        curl_easy_setopt(curl, CURLOPT_COOKIELIST, line.c_str());
    }
}

// Write every cookie the engine holds back to `file` (call before cleanup).
static void save_cookies(CURL* curl, const std::string& file) {
    if (file.empty()) return;

    curl_slist* list = nullptr;
    if (curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &list) != CURLE_OK || !list)
        return;

    std::ofstream out(ipt::fs_path(file), std::ios::binary | std::ios::trunc);
    if (out) {
        out << "# Netscape HTTP Cookie File\n";
        for (curl_slist* p = list; p; p = p->next)
            out << p->data << '\n';
    }
    curl_slist_free_all(list);
}

// Remove the cookie file so the next request starts with an empty jar. Cookie
// state is held only in this file (each request reloads it from disk), so there
// is no in-memory jar to clear. Best-effort: a missing file is already "clear".
void HttpClient::clear_cookies() const {
    if (m_cookieFile.empty()) return;
    std::error_code ec;
    std::filesystem::remove(ipt::fs_path(m_cookieFile), ec);
}

// ── Retry helpers ─────────────────────────────────────────────────────────────

// Transient transport failures worth retrying (a network blip, a dropped or
// reset connection, a stalled transfer, DNS briefly unavailable) — as opposed to
// a definite HTTP/content problem (wrong status, bad range, changed ETag), which
// the caller always treats as a hard failure. A short outage that recovers
// (e.g. wifi dropped and came back) surfaces here as a recv/partial/connect code.
static bool is_retryable_curl(CURLcode rc) {
    switch (rc) {
        case CURLE_OPERATION_TIMEDOUT:    // 28 — stalled past low-speed-time
        case CURLE_RECV_ERROR:            // 56 — failure receiving from peer (reset)
        case CURLE_SEND_ERROR:            // 55 — failure sending to peer
        case CURLE_PARTIAL_FILE:          // 18 — connection dropped mid-transfer
        case CURLE_GOT_NOTHING:           // 52 — empty reply, peer closed early
        case CURLE_COULDNT_CONNECT:       //  7 — connection failed (net just back)
        case CURLE_COULDNT_RESOLVE_HOST:  //  6 — DNS temporarily unavailable
            return true;
        default:
            return false;
    }
}

// ── Config ─────────────────────────────────────────────────────────────────────

static constexpr const char* USER_AGENT =
    "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";

// ── Retry config: API calls ───────────────────────────────────────────────────
static constexpr int API_MAX_RETRIES  = 5;
static constexpr int API_BACKOFF_S[]  = { 1, 2, 4, 8, 15 };  // total: 30 s

// ── Retry config: file downloads ──────────────────────────────────────────────
static constexpr int DL_MAX_RETRIES   = 5;
static constexpr int DL_BACKOFF_S[]   = { 3, 6, 12, 24, 30 };  // total: 75 s

// ── HttpClient ────────────────────────────────────────────────────────────────

HttpClient::HttpClient(const std::string& cookieFile)
    : m_cookieFile(cookieFile)
{
    curl_global_init(CURL_GLOBAL_ALL);
}

HttpClient::~HttpClient() { curl_global_cleanup(); }

HttpResponse HttpClient::post(const std::string& url,
                  const std::string& body,
                  const std::map<std::string, std::string>& reqHeaders) const
{
    return perform("POST", url, body, reqHeaders);
}

HttpResponse HttpClient::get(const std::string& url,
                 const std::map<std::string, std::string>& reqHeaders) const
{
    return perform("GET", url, "", reqHeaders);
}

HttpResponse HttpClient::get_range(const std::string& url,
                                   const std::string& rangeSpec,
                                   size_t             maxBytes,
                                   const std::map<std::string, std::string>& reqHeaders) const
{
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");

    HttpResponse resp;
    std::string  respBody;
    CappedBuf    sink{ &respBody, maxBytes };

    curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT,      USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);   // the .ipa URL may redirect
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        60L);
    curl_easy_setopt(curl, CURLOPT_RANGE,          rangeSpec.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  capped_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &sink);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA,     &resp.headers);
    load_cookies(curl, m_cookieFile);

    struct curl_slist* hdrs = nullptr;
    for (auto& [k, v] : reqHeaders) {
        std::string h = k + ": " + v;
        hdrs = curl_slist_append(hdrs, h.c_str());
    }
    if (hdrs) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(curl);
    if (hdrs) curl_slist_free_all(hdrs);

    if (rc != CURLE_OK) {
        save_cookies(curl, m_cookieFile);
        curl_easy_cleanup(curl);
        throw std::runtime_error(std::string("range GET failed: ") + curl_easy_strerror(rc));
    }

    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    save_cookies(curl, m_cookieFile);
    curl_easy_cleanup(curl);
    resp.statusCode = static_cast<int>(code);
    resp.body       = std::move(respBody);
    return resp;
}

void HttpClient::download(const std::string& url,
              const std::string& destPath,
              int64_t            rangeStart,
              std::function<void(int64_t, int64_t)> progress) const
{
    int64_t  currentStart = rangeStart;
    CURLcode rc           = CURLE_OK;
    int64_t  knownTotal   = 0;  // carry total across retries for progress continuity

    for (int attempt = 0; ; ++attempt) {
        // ── Back-off before retry ────────────────────────────────────────
        if (attempt > 0) {
            if (!is_retryable_curl(rc) || attempt > DL_MAX_RETRIES) break;

            int delay = DL_BACKOFF_S[attempt - 1];
            if (m_debug)
                fprintf(stderr,
                    "\n[WARN] Download interrupted (%s), resuming from byte %lld "
                    "in %ds... (attempt %d/%d)\n",
                    curl_easy_strerror(rc),
                    static_cast<long long>(currentStart),
                    delay, attempt, DL_MAX_RETRIES);
            std::this_thread::sleep_for(std::chrono::seconds(delay));
        }

        // ── Open file ────────────────────────────────────────────────────
        // Append when resuming so previously written bytes are preserved.
        const char* openMode = (currentStart > 0) ? "ab" : "wb";
        FILE* fp = ipt::fopen_utf8(destPath, openMode);
        if (!fp) throw std::runtime_error("failed to open file: " + destPath);

        CURL* curl = curl_easy_init();
        if (!curl) { fclose(fp); throw std::runtime_error("curl_easy_init failed"); }

        DownloadState ds;
        ds.fp         = fp;
        ds.progress   = progress;
        ds.rangeStart = currentStart;
        ds.received   = 0;
        ds.total      = knownTotal;  // preserve total so progress bar is smooth on retry

        std::map<std::string, std::string> respHeaders;

        curl_easy_setopt(curl, CURLOPT_URL,             url.c_str());
        curl_easy_setopt(curl, CURLOPT_USERAGENT,       USER_AGENT);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,  1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  1L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,  15L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 512L);  // abort if < 512 B/s
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,  30L);   // for more than 30 s
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   file_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,       &ds);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,xferinfo_cb);
        curl_easy_setopt(curl, CURLOPT_XFERINFODATA,    &ds);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS,      0L);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION,  header_cb);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA,      &respHeaders);
        load_cookies(curl, m_cookieFile);

        if (currentStart > 0) {
            std::string range = std::to_string(currentStart) + "-";
            curl_easy_setopt(curl, CURLOPT_RANGE, range.c_str());
        }

        // ── Perform ──────────────────────────────────────────────────────
        rc = curl_easy_perform(curl);

        knownTotal     = ds.total;       // save for next attempt
        currentStart  += ds.received;    // advance offset by bytes actually written

        fclose(fp);
        save_cookies(curl, m_cookieFile);
        curl_easy_cleanup(curl);

        if (rc == CURLE_OK) return;      // success — done
    }

    throw std::runtime_error(
        std::string("Download failed after retries: ") + curl_easy_strerror(rc));
}

// ── Parallel download ───────────────────────────────────────────────────────────
namespace {

constexpr int64_t kParallelThreshold = 128LL * 1024 * 1024;  // only files >= 128 MiB
constexpr int     kParallelConns     = 4;

// Per-connection state for the parallel writer/progress callbacks.
struct PartState {
    FILE*                 fp        = nullptr;
    std::atomic<int64_t>* counter   = nullptr;  // this part's bytes in the current attempt
    std::atomic<bool>*    cancelled = nullptr;
};

size_t part_write_cb(char* ptr, size_t size, size_t nmemb, void* ud) {
    auto* ps = reinterpret_cast<PartState*>(ud);
    return fwrite(ptr, size, nmemb, ps->fp) * size;   // short write => curl aborts
}

int part_xfer_cb(void* ud, curl_off_t, curl_off_t dlnow, curl_off_t, curl_off_t) {
    auto* ps = reinterpret_cast<PartState*>(ud);
    if (ps->cancelled->load(std::memory_order_relaxed)) return 1;  // abort this transfer
    // Absolute bytes for this attempt; a chunk retry restarts the part from 0, so
    // storing (not adding) keeps the aggregate correct across retries.
    ps->counter->store(static_cast<int64_t>(dlnow), std::memory_order_relaxed);
    return 0;
}

// Per-part chunk retries, but only for transport/timeout failures (is_retryable_curl).
constexpr int   kPartRetries    = 3;
constexpr int   kPartBackoffS[] = { 1, 2, 4 };

// Total size out of a "bytes A-B/TOTAL" Content-Range header. -1 if absent/bad.
int64_t content_range_total(const std::map<std::string, std::string>& h) {
    auto it = h.find("content-range");
    if (it == h.end()) return -1;
    auto slash = it->second.rfind('/');
    if (slash == std::string::npos) return -1;
    std::string t = it->second.substr(slash + 1);
    if (t.empty() || t == "*") return -1;
    try { return std::stoll(t); } catch (...) { return -1; }
}

// Suffix for a debug line printed while the live progress bar shares the
// terminal: erase from the cursor to end of line so the bar's leftover tail
// doesn't trail the text. Empty when stderr isn't a tty (redirected to a file),
// so captured logs don't get control bytes.
const char* dbg_eol() {
#if defined(_WIN32)
    return _isatty(_fileno(stderr)) ? "\x1b[K" : "";
#else
    return isatty(fileno(stderr)) ? "\x1b[K" : "";
#endif
}

// Chunk-queue download: a chunk's bytes are collected in memory (so they can be
// md5-checked before being committed to the file) while progress/cancel flow
// through the same atomics the reporter reads.
struct ChunkDl {
    std::string*          buf       = nullptr;  // accumulates this chunk's bytes
    std::atomic<int64_t>* inflight  = nullptr;  // bytes received in the current attempt
    std::atomic<bool>*    cancelled = nullptr;
};

size_t chunk_write_cb(char* ptr, size_t size, size_t nmemb, void* ud) {
    auto* c = reinterpret_cast<ChunkDl*>(ud);
    c->buf->append(ptr, size * nmemb);
    return size * nmemb;
}

int chunk_xfer_cb(void* ud, curl_off_t, curl_off_t dlnow, curl_off_t, curl_off_t) {
    auto* c = reinterpret_cast<ChunkDl*>(ud);
    if (c->cancelled->load(std::memory_order_relaxed)) return 1;  // abort this transfer
    c->inflight->store(static_cast<int64_t>(dlnow), std::memory_order_relaxed);
    return 0;
}

} // namespace

bool HttpClient::download_parallel(const std::string& url,
                                   const std::string& destPath,
                                   std::function<void(int64_t, int64_t)> progress,
                                   int64_t chunkSize,
                                   int     chunkCount,
                                   ChunkVerifier verifyChunk) const
{
    namespace fs = std::filesystem;
    std::error_code ec;

    auto decline = [&](const char* why) -> bool {
        if (m_debug) fprintf(stderr, "[DEBUG] parallel download declined: %s\n", why);
        return false;
    };

    // A resumable partial already on disk: let single-connection download() resume
    // it rather than restarting from scratch here.
    if (fs::exists(ipt::fs_path(destPath), ec) &&
        fs::file_size(ipt::fs_path(destPath), ec) > 0)
        return decline("a resumable partial file is already on disk");

    // Probe for the total size and a validator; any surprise => decline.
    HttpResponse probe;
    try { probe = get_range(url, "0-0", 64 * 1024); }
    catch (const std::exception&) { return decline("probe request failed"); }
    if (probe.statusCode != 206) return decline("server did not honour Range (no 206)");

    int64_t total = content_range_total(probe.headers);
    if (total < 0) return decline("no Content-Range on the probe");

    // The size threshold only guards the equal-split path (splitting a small file
    // into 4 big parts isn't worth it). When the response carried a chunk manifest
    // we have Apple's own chunk layout and per-chunk md5s, so chunk-queue it
    // regardless of size — workers that find the queue already drained just stop.
    const bool haveManifest = (chunkSize > 0 && chunkCount > 0);
    if (!haveManifest && total < kParallelThreshold)
        return decline("file is below the 128 MiB parallel threshold");

    // ETag: required for the equal-split path (it's the only cross-connection
    // consistency guard there); optional for the chunk-queue path, where each
    // chunk's md5 from the manifest is the real integrity check.
    std::string etag;
    bool        strongEtag = false;
    auto etIt = probe.headers.find("etag");
    if (etIt != probe.headers.end()) {
        etag = etIt->second;
        strongEtag = (etag.size() >= 2 && etag.front() == '"' && etag.rfind("W/", 0) != 0);
    }

    // ── Chunk-queue strategy (when the download response carried a manifest) ────
    // 4 workers pull free chunk indices off a shared counter; each fetches its
    // chunk's byte range, md5-checks it against the manifest, and on success grabs
    // the next free index. A slow connection only holds up its own current chunk,
    // not the whole download; a corrupt chunk is re-fetched in place.
    if (haveManifest) {
        const int64_t expect = (total + chunkSize - 1) / chunkSize;
        if (expect != chunkCount)
            return decline("chunk manifest does not match server size");

        if (m_debug)
            fprintf(stderr, "[DEBUG] parallel download (chunk queue): %d workers, "
                    "%.1f MiB total, %d chunks of %lld, ETag %s\n",
                    kParallelConns, (double)total / (1024.0 * 1024.0), chunkCount,
                    (long long)chunkSize, strongEtag ? etag.c_str() : "(none/weak)");

        // One temp file unique to this process + call, preallocated to the full
        // size so workers write their chunk at its offset without racing on file
        // extension. Published to destPath with a rename only on full success.
#if defined(_WIN32)
        long pid = _getpid();
#else
        long pid = static_cast<long>(getpid());
#endif
        std::random_device rd;
        uint64_t rnd = (static_cast<uint64_t>(rd()) << 32) ^ rd();
        char suffix[48];
        snprintf(suffix, sizeof(suffix), ".dl-%ld-%016llx",
                 pid, static_cast<unsigned long long>(rnd));
        std::string tmp = destPath + suffix;

        { FILE* f = ipt::fopen_utf8(tmp, "wb"); if (!f) return false; fclose(f); }
        fs::resize_file(ipt::fs_path(tmp), (uintmax_t)total, ec);
        if (ec) { fs::remove(ipt::fs_path(tmp), ec); return false; }
        struct FileGuard {
            fs::path p; bool commit = false;
            ~FileGuard() { if (!commit) { std::error_code e; fs::remove(p, e); } }
        } fileGuard{ ipt::fs_path(tmp), false };

        std::atomic<int>     nextChunk{0};
        std::atomic<bool>    cancelled{false};
        std::atomic<int>     finished{0};
        std::atomic<int64_t> committed{0};
        std::vector<std::string> workerErr(kParallelConns);
        std::unique_ptr<std::atomic<int64_t>[]> inflight(new std::atomic<int64_t>[kParallelConns]);
        for (int i = 0; i < kParallelConns; ++i) inflight[i].store(0);

        auto worker = [&](int wk) {
            struct FinishGuard { std::atomic<int>& c; ~FinishGuard() { c.fetch_add(1); } } fg{ finished };
            auto sleep_cancellable = [&](int secs) {
                for (int i = 0; i < secs * 5 && !cancelled.load(); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
            };

            FILE* out = ipt::fopen_utf8(tmp, "r+b");
            if (!out) { workerErr[wk] = "cannot open output"; cancelled.store(true); return; }

            CURL* curl = curl_easy_init();
            if (!curl) { fclose(out); workerErr[wk] = "curl init failed"; cancelled.store(true); return; }

            std::string buf;
            ChunkDl cd; cd.buf = &buf; cd.inflight = &inflight[wk]; cd.cancelled = &cancelled;

            // Built once and reused for every chunk this worker fetches, so the
            // TCP/TLS connection is kept alive across chunks (only the Range
            // changes per request).
            struct curl_slist* hdrs = nullptr;
            hdrs = curl_slist_append(hdrs, "Accept-Encoding: identity");  // exact byte ranges
            std::string ifRange;
            if (strongEtag) { ifRange = "If-Range: " + etag; hdrs = curl_slist_append(hdrs, ifRange.c_str()); }

            curl_easy_setopt(curl, CURLOPT_URL,             url.c_str());
            curl_easy_setopt(curl, CURLOPT_USERAGENT,       USER_AGENT);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,  1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  1L);
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,  15L);
            curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 512L);   // abort a stalled chunk
            curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,  30L);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER,      hdrs);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   chunk_write_cb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA,       &cd);
            curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,chunk_xfer_cb);
            curl_easy_setopt(curl, CURLOPT_XFERINFODATA,    &cd);
            curl_easy_setopt(curl, CURLOPT_NOPROGRESS,      0L);
            load_cookies(curl, m_cookieFile);   // read-only; workers never write the jar

            for (;;) {
                if (cancelled.load()) break;
                int idx = nextChunk.fetch_add(1);
                if (idx >= chunkCount) break;   // queue drained — this worker is done

                const int64_t off = (int64_t)idx * chunkSize;
                const int64_t len = std::min<int64_t>(chunkSize, total - off);
                std::string rangeSpec = std::to_string(off) + "-" + std::to_string(off + len - 1);

                bool ok = false;
                for (int attempt = 0; ; ++attempt) {
                    if (cancelled.load()) break;
                    buf.clear();
                    inflight[wk].store(0);
                    curl_easy_setopt(curl, CURLOPT_RANGE, rangeSpec.c_str());

                    CURLcode rc = curl_easy_perform(curl);
                    long code = 0;
                    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
                    if (cancelled.load()) break;

                    if (rc != CURLE_OK) {
                        // Only a transport/timeout error retries this chunk.
                        if (is_retryable_curl(rc) && attempt < kPartRetries) {
                            if (m_debug)
                                fprintf(stderr, "[DEBUG] chunk %d: %s - retry %d/%d%s\n",
                                        idx + 1, curl_easy_strerror(rc), attempt + 1, kPartRetries, dbg_eol());
                            sleep_cancellable(kPartBackoffS[attempt]);
                            continue;
                        }
                        workerErr[wk] = std::string("chunk transfer failed: ") + curl_easy_strerror(rc);
                        break;  // hard fail
                    }
                    if (code != 206)              { workerErr[wk] = "server ignored range"; break; }
                    if ((int64_t)buf.size() != len) { workerErr[wk] = "short chunk"; break; }
                    if (verifyChunk && !verifyChunk(idx, (const uint8_t*)buf.data(), buf.size())) {
                        // md5 mismatch → re-fetch this chunk (bounded), distinct
                        // from a transport error but handled on the same budget.
                        if (attempt < kPartRetries) {
                            if (m_debug)
                                fprintf(stderr, "[DEBUG] chunk %d md5 mismatch - refetch %d/%d%s\n",
                                        idx + 1, attempt + 1, kPartRetries, dbg_eol());
                            sleep_cancellable(kPartBackoffS[attempt]);
                            continue;
                        }
                        workerErr[wk] = "chunk md5 still bad after refetch";
                        break;
                    }
                    ok = true;
                    break;
                }
                if (!ok) { cancelled.store(true); break; }

                // Commit the verified bytes to the file at this chunk's offset.
#if defined(_WIN32)
                if (_fseeki64(out, off, SEEK_SET) != 0)
#else
                if (fseeko(out, (off_t)off, SEEK_SET) != 0)
#endif
                { workerErr[wk] = "seek failed"; cancelled.store(true); break; }
                if (fwrite(buf.data(), 1, buf.size(), out) != buf.size())
                { workerErr[wk] = "write failed"; cancelled.store(true); break; }

                committed.fetch_add(len);
                inflight[wk].store(0);

                if (m_debug)
                    fprintf(stderr, "[DEBUG] chunk %d/%d md5 ok (%lld bytes)%s\n",
                            idx + 1, chunkCount, (long long)len, dbg_eol());
            }

            fflush(out);
            fclose(out);
            curl_slist_free_all(hdrs);
            curl_easy_cleanup(curl);
        };

        std::vector<std::thread> threads;
        threads.reserve(kParallelConns);
        for (int i = 0; i < kParallelConns; ++i) threads.emplace_back(worker, i);

        auto sum_progress = [&]() {
            int64_t s = committed.load();
            for (int i = 0; i < kParallelConns; ++i) s += inflight[i].load();
            return s > total ? total : s;
        };
        while (finished.load() < kParallelConns) {
            if (progress) progress(sum_progress(), total);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        for (auto& t : threads) t.join();

        for (const auto& e : workerErr) {
            if (!e.empty()) {
                if (m_debug)
                    fprintf(stderr, "[DEBUG] parallel download failed (%s) - falling back to single stream\n",
                            e.c_str());
                return false;   // fileGuard removes tmp
            }
        }

        // Success — publish the temp file as the destination.
        fs::remove(ipt::fs_path(destPath), ec);
        fs::rename(ipt::fs_path(tmp), ipt::fs_path(destPath), ec);
        if (ec) {
            if (m_debug)
                fprintf(stderr, "[DEBUG] parallel download: rename failed (%s)\n", ec.message().c_str());
            return false;
        }
        fileGuard.commit = true;

        if (progress) progress(total, total);
        if (m_debug)
            fprintf(stderr, "[DEBUG] parallel download complete (%d workers, %d chunks)\n",
                    kParallelConns, chunkCount);
        return true;
    }

    // ── Equal-split fallback (no manifest): split into kParallelConns contiguous
    // parts, one per connection. Needs a strong ETag as the only cross-connection
    // consistency guard, since there are no per-chunk hashes here.
    if (!strongEtag) return decline("ETag is weak or not a quoted strong validator");

    if (m_debug)
        fprintf(stderr, "[DEBUG] parallel download: %d connections, %.1f MiB total, ETag %s\n",
                kParallelConns, (double)total / (1024.0 * 1024.0), etag.c_str());

    // Staging directory unique to this process + this call, so two ipatool runs
    // (even on the same destination) never collide on part files.
#if defined(_WIN32)
    long pid = _getpid();
#else
    long pid = static_cast<long>(getpid());
#endif
    std::random_device rd;
    uint64_t rnd = (static_cast<uint64_t>(rd()) << 32) ^ rd();
    char suffix[48];
    snprintf(suffix, sizeof(suffix), ".parts-%ld-%016llx",
             pid, static_cast<unsigned long long>(rnd));
    std::string staging = destPath + suffix;

    if (!fs::create_directory(ipt::fs_path(staging), ec) || ec) return false;
    struct DirGuard {
        fs::path p;
        ~DirGuard() { std::error_code e; fs::remove_all(p, e); }
    } dirGuard{ ipt::fs_path(staging) };

    const int64_t chunk = total / kParallelConns;

    std::atomic<bool> cancelled{false};
    std::atomic<int>  finished{0};
    std::vector<std::string> partErr(kParallelConns);
    std::vector<std::string> partPath(kParallelConns);
    // One progress counter per worker so a chunk retry can reset just its own
    // contribution; the reporter thread sums them.
    std::unique_ptr<std::atomic<int64_t>[]> partReceived(new std::atomic<int64_t>[kParallelConns]);
    for (int i = 0; i < kParallelConns; ++i) partReceived[i].store(0);

    auto worker = [&](int idx) {
        // Each worker touches only its own slot; main reads them after join.
        struct FinishGuard { std::atomic<int>& c; ~FinishGuard() { c.fetch_add(1); } } fg{ finished };

        auto sleep_cancellable = [&](int secs) {
            for (int i = 0; i < secs * 5 && !cancelled.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
        };

        const int64_t start = chunk * idx;
        const int64_t end   = (idx == kParallelConns - 1) ? (total - 1) : (start + chunk - 1);
        const int64_t want  = end - start + 1;
        std::string   path  = staging + "/" + std::to_string(idx);
        partPath[idx] = path;

        for (int attempt = 0; ; ++attempt) {
            if (cancelled.load()) return;       // another worker already failed hard

            // Each attempt re-fetches the whole chunk from scratch (truncate "wb").
            partReceived[idx].store(0);
            FILE* fp = ipt::fopen_utf8(path, "wb");
            if (!fp) { partErr[idx] = "cannot open part file"; cancelled.store(true); return; }

            CURL* curl = curl_easy_init();
            if (!curl) { fclose(fp); partErr[idx] = "curl init failed"; cancelled.store(true); return; }

            PartState ps;
            ps.fp = fp; ps.counter = &partReceived[idx]; ps.cancelled = &cancelled;

            std::map<std::string, std::string> respHeaders;
            std::string rangeSpec = std::to_string(start) + "-" + std::to_string(end);

            struct curl_slist* hdrs = nullptr;
            hdrs = curl_slist_append(hdrs, "Accept-Encoding: identity");  // exact byte ranges
            std::string ifRange = "If-Range: " + etag;
            hdrs = curl_slist_append(hdrs, ifRange.c_str());

            curl_easy_setopt(curl, CURLOPT_URL,             url.c_str());
            curl_easy_setopt(curl, CURLOPT_USERAGENT,       USER_AGENT);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,  1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  1L);
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,  15L);
            curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 512L);   // abort a stalled part
            curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,  30L);
            curl_easy_setopt(curl, CURLOPT_RANGE,           rangeSpec.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER,      hdrs);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   part_write_cb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA,       &ps);
            curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,part_xfer_cb);
            curl_easy_setopt(curl, CURLOPT_XFERINFODATA,    &ps);
            curl_easy_setopt(curl, CURLOPT_NOPROGRESS,      0L);
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION,  header_cb);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA,      &respHeaders);
            load_cookies(curl, m_cookieFile);   // read-only; workers never write the jar

            CURLcode rc = curl_easy_perform(curl);
            long code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            fclose(fp);
            curl_slist_free_all(hdrs);
            curl_easy_cleanup(curl);

            if (cancelled.load()) return;       // aborted mid-transfer by another hard failure

            if (rc != CURLE_OK) {
                // Only a transport/timeout error is worth retrying this chunk; a
                // bad HTTP response is handled below and is never chunk-retried.
                if (is_retryable_curl(rc) && attempt < kPartRetries) {
                    if (m_debug)
                        fprintf(stderr, "[DEBUG] parallel part %d: %s - retry %d/%d\n",
                                idx, curl_easy_strerror(rc), attempt + 1, kPartRetries);
                    sleep_cancellable(kPartBackoffS[attempt]);
                    continue;
                }
                partErr[idx] = std::string("range transfer failed: ") + curl_easy_strerror(rc);
                cancelled.store(true);
                return;
            }

            // Transfer succeeded at the transport level — now validate the result.
            // These are "something else bad", not timeouts, so they are NOT retried:
            // they mean the server/representation is wrong, and the whole parallel
            // attempt falls back to a single stream.
            if (code != 206) { partErr[idx] = "server ignored range"; cancelled.store(true); return; }
            if (content_range_total(respHeaders) != total) {
                partErr[idx] = "range total mismatch"; cancelled.store(true); return;
            }
            auto et = respHeaders.find("etag");
            if (et != respHeaders.end() && et->second != etag) {
                partErr[idx] = "file changed mid-download"; cancelled.store(true); return;
            }
            std::error_code sz;
            if (static_cast<int64_t>(fs::file_size(ipt::fs_path(path), sz)) != want || sz) {
                partErr[idx] = "incomplete range"; cancelled.store(true); return;
            }
            return;   // this chunk is done
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(kParallelConns);
    for (int i = 0; i < kParallelConns; ++i) threads.emplace_back(worker, i);

    // Report aggregate progress (sum of per-worker counters) while workers run.
    auto sum_received = [&]() {
        int64_t s = 0;
        for (int i = 0; i < kParallelConns; ++i) s += partReceived[i].load();
        return s;
    };
    while (finished.load() < kParallelConns) {
        if (progress) progress(sum_received(), total);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    for (auto& t : threads) t.join();
    if (progress) progress(sum_received(), total);

    for (const auto& e : partErr) {
        if (!e.empty()) {
            if (m_debug)
                fprintf(stderr, "[DEBUG] parallel download failed (%s) - falling back to single stream\n",
                        e.c_str());
            return false;   // caller falls back
        }
    }

    // Assemble the parts, in order, into the destination.
    FILE* out = ipt::fopen_utf8(destPath, "wb");
    if (!out) return false;
    std::vector<char> buf(1 << 20);
    bool ok = true;
    for (int i = 0; i < kParallelConns && ok; ++i) {
        FILE* in = ipt::fopen_utf8(partPath[i], "rb");
        if (!in) { ok = false; break; }
        size_t n;
        while ((n = fread(buf.data(), 1, buf.size(), in)) > 0) {
            if (fwrite(buf.data(), 1, n, out) != n) { ok = false; break; }
        }
        fclose(in);
    }
    if (ok && fflush(out) != 0) ok = false;
    fclose(out);
    if (!ok) { fs::remove(ipt::fs_path(destPath), ec); return false; }

    if (progress) progress(total, total);
    if (m_debug) fprintf(stderr, "[DEBUG] parallel download complete (%d connections)\n", kParallelConns);
    return true;
}

bool HttpClient::download_range(const std::string& url,
                                int64_t start, int64_t end,
                                std::string& out) const
{
    const int64_t     want      = end - start + 1;
    const std::string rangeSpec = std::to_string(start) + "-" + std::to_string(end);

    for (int attempt = 0; ; ++attempt) {
        if (attempt > 0)
            std::this_thread::sleep_for(std::chrono::seconds(kPartBackoffS[attempt - 1]));

        out.clear();
        CURL* curl = curl_easy_init();
        if (!curl) return false;

        std::map<std::string, std::string> respHeaders;
        struct curl_slist* hdrs = nullptr;
        hdrs = curl_slist_append(hdrs, "Accept-Encoding: identity");  // exact byte range

        curl_easy_setopt(curl, CURLOPT_URL,             url.c_str());
        curl_easy_setopt(curl, CURLOPT_USERAGENT,       USER_AGENT);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,  1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  1L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,  15L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 512L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,  30L);
        curl_easy_setopt(curl, CURLOPT_RANGE,           rangeSpec.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER,      hdrs);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   body_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,       &out);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION,  header_cb);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA,      &respHeaders);
        load_cookies(curl, m_cookieFile);   // read-only

        CURLcode rc = curl_easy_perform(curl);
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);

        if (rc != CURLE_OK) {
            // Only a transport/timeout error is worth retrying; everything else is
            // a hard failure handled by the caller's full-redownload fallback.
            if (is_retryable_curl(rc) && attempt < kPartRetries) {
                if (m_debug)
                    fprintf(stderr, "[DEBUG] range refetch %lld-%lld: %s - retry %d/%d\n",
                            (long long)start, (long long)end, curl_easy_strerror(rc),
                            attempt + 1, kPartRetries);
                continue;
            }
            return false;
        }
        if (code != 206) return false;                   // server ignored the range
        if (static_cast<int64_t>(out.size()) != want) return false;  // wrong length
        return true;
    }
}

HttpResponse HttpClient::perform(const std::string& method,
                     const std::string& url,
                     const std::string& body,
                     const std::map<std::string, std::string>& reqHeaders) const
{
    CURLcode rc      = CURLE_OK;
    int      attempt = 0;

    for (;;) {
        // ── Back-off before retry ────────────────────────────────────────
        if (attempt > 0) {
            int delay = API_BACKOFF_S[attempt - 1];
            if (m_debug)
                fprintf(stderr,
                    "[WARN] HTTP %s failed (%s), retrying in %ds... (%d/%d)\n",
                    method.c_str(), curl_easy_strerror(rc),
                    delay, attempt, API_MAX_RETRIES);
            std::this_thread::sleep_for(std::chrono::seconds(delay));
        }

        // ── Setup curl ───────────────────────────────────────────────────
        CURL* curl = curl_easy_init();
        if (!curl) throw std::runtime_error("curl_easy_init failed");

        HttpResponse resp;
        std::string  respBody;

        curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
        curl_easy_setopt(curl, CURLOPT_USERAGENT,      USER_AGENT);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT,        30L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  body_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &respBody);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA,     &resp.headers);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        load_cookies(curl, m_cookieFile);

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

        // ── Perform ──────────────────────────────────────────────────────
        rc = curl_easy_perform(curl);
        if (hdrs) curl_slist_free_all(hdrs);

        if (rc == CURLE_OK) {
            long code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            save_cookies(curl, m_cookieFile);
            curl_easy_cleanup(curl);
            resp.statusCode = static_cast<int>(code);
            resp.body       = std::move(respBody);
            if (m_observer) m_observer(method, url, resp);
            return resp;
        }

        save_cookies(curl, m_cookieFile);
        curl_easy_cleanup(curl);
        ++attempt;

        if (!is_retryable_curl(rc) || attempt > API_MAX_RETRIES) break;
    }

    // A name-resolution failure gets its own type so callers (e.g. list_purchases)
    // can distinguish it from other transport errors and fall back. Not retried
    // above anyway — is_retryable_curl() only retries timeouts. Message text is
    // kept identical to the generic case for log continuity.
    if (rc == CURLE_COULDNT_RESOLVE_HOST || rc == CURLE_COULDNT_RESOLVE_PROXY)
        throw DnsResolveError(
            std::string("HTTP request failed: ") + curl_easy_strerror(rc));

    throw std::runtime_error(
        std::string("HTTP request failed: ") + curl_easy_strerror(rc));
}
