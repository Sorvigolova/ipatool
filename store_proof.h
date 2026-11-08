#pragma once

#include "store_adi.h"
#include <string_view>

namespace ipt {

inline constexpr const char* store_user_agent =
    "Configurator/2.21 (Macintosh; OS X 15.7; 24G222) AppleWebKit/0620.2.4.11.6";

inline bool store_auth_url(std::string_view url) {
    if (url.find_first_of("#\r\n\\") != url.npos) return false;
    url = url.substr(0, url.find('?'));
    return url == "https://auth.itunes.apple.com/auth/v1/native"
        || url == "https://auth.itunes.apple.com/auth/v1/native/";
}

inline bool store_proof_url(std::string_view url) {
    if (store_auth_url(url)) return true;
    if (url.find_first_of("#\r\n\\") != url.npos) return false;
    url = url.substr(0, url.find('?'));
    constexpr std::string_view dispatch = "https://downloaddispatch.itunes.apple.com";
    if (url.starts_with(dispatch)) {
        const auto path = url.substr(dispatch.size());
        return path == "/WebObjects/DownloadDispatch.woa/wa/ent/download"
            || path == "/r/redownload" || path == "/up/updateProduct";
    }
    constexpr std::string_view https = "https://";
    if (!url.starts_with(https)) return false;
    url.remove_prefix(https.size());
    const auto slash = url.find('/');
    if (slash == url.npos) return false;
    const auto host = url.substr(0, slash);
    const auto path = url.substr(slash);
    if (path != "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct"
        && path != "/WebObjects/MZFinance.woa/wa/buyProduct"
        && path != "/WebObjects/MZBuy.woa/wa/buyProduct") return false;
    if (host == "buy.itunes.apple.com") return true;
    constexpr std::string_view suffix = "-buy.itunes.apple.com";
    if (!host.starts_with('p') || !host.ends_with(suffix) || host.size() <= suffix.size() + 1) return false;
    return host.substr(1, host.size() - suffix.size() - 1).find_first_not_of("0123456789") == host.npos;
}

inline HttpResponse store_proof_post(HttpClient& http, const std::string& url, const std::string& body,
                                    std::map<std::string, std::string> headers, const std::string& guid) {
    if (!store_proof_url(url)) throw IpaError("unexpected endpoint for Store AMD proof");
    headers["User-Agent"] = store_user_agent;
    auto proof = store_proof_headers();
    headers.merge(proof);
    auto response = http.post(url, body, headers);
    const auto action = response.headers.find("x-apple-amd-action");
    if (response.statusCode != 200 || action == response.headers.end() || action->second != "SP")
        return response;
    const auto challenge = response.headers.find("x-apple-amd-data");
    if (challenge == response.headers.end() || challenge->second.empty())
        throw IpaError("Apple returned an empty Store AMD challenge");
    for (auto& [key, value] : store_proof_headers(challenge->second, guid)) headers[key] = std::move(value);
    return http.post(url, body, headers);
}

} // namespace ipt
