#include "http_client.h"
#include <curl/curl.h>
#include <stdexcept>
#include <cctype>
#include <cstdio>
#include <thread>
#include <chrono>

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

// ── Retry helpers ─────────────────────────────────────────────────────────────

// Only timeout errors are retried — other failures surface immediately.
static bool is_retryable_curl(CURLcode rc) {
    return rc == CURLE_OPERATION_TIMEDOUT;
}

// ── Config ─────────────────────────────────────────────────────────────────────

static constexpr const char* USER_AGENT =
    "Configurator/2.15 (Macintosh; OS X 11.0.0; 16G29) AppleWebKit/2603.3.8";

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
        FILE* fp = fopen(destPath.c_str(), openMode);
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
        if (!m_cookieFile.empty()) {
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, m_cookieFile.c_str());
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR,  m_cookieFile.c_str());
        } else {
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
        }

        if (currentStart > 0) {
            std::string range = std::to_string(currentStart) + "-";
            curl_easy_setopt(curl, CURLOPT_RANGE, range.c_str());
        }

        // ── Perform ──────────────────────────────────────────────────────
        rc = curl_easy_perform(curl);

        knownTotal     = ds.total;       // save for next attempt
        currentStart  += ds.received;    // advance offset by bytes actually written

        fclose(fp);
        curl_easy_cleanup(curl);

        if (rc == CURLE_OK) return;      // success — done
    }

    throw std::runtime_error(
        std::string("Download failed after retries: ") + curl_easy_strerror(rc));
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
        if (!m_cookieFile.empty()) {
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, m_cookieFile.c_str());
            curl_easy_setopt(curl, CURLOPT_COOKIEJAR,  m_cookieFile.c_str());
        } else {
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
        }

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
            curl_easy_cleanup(curl);
            resp.statusCode = static_cast<int>(code);
            resp.body       = std::move(respBody);
            return resp;
        }

        curl_easy_cleanup(curl);
        ++attempt;

        if (!is_retryable_curl(rc) || attempt > API_MAX_RETRIES) break;
    }

    throw std::runtime_error(
        std::string("HTTP request failed: ") + curl_easy_strerror(rc));
}
