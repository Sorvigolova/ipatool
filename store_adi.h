#pragma once

#include <map>
#include <string>
#include <string_view>

class HttpClient;

namespace ipt {
bool fetch_remote_zip_entry(const HttpClient& http, const std::string& url,
                            std::string_view name, std::string& output);

// Device proof shared by authentication and commerce. No account data is passed to ADI.
std::map<std::string, std::string> store_proof_headers(
    const std::string& challenge = {}, const std::string& guid = {});
}
