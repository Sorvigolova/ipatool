#pragma once
// Thin wrapper around nlohmann/json for the parts ipatool needs
// (search & lookup responses come back as JSON).
// We use the single-header nlohmann/json.hpp which must be present at build time.

#include "ipatool.h"
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

static App app_from_json(const json& j) {
    App a;
    if (j.contains("trackId")   && j["trackId"].is_number())   a.id       = j["trackId"].get<int64_t>();
    if (j.contains("bundleId")  && j["bundleId"].is_string())  a.bundleID = j["bundleId"].get<std::string>();
    if (j.contains("trackName") && j["trackName"].is_string()) a.name     = j["trackName"].get<std::string>();
    if (j.contains("version")   && j["version"].is_string())   a.version  = j["version"].get<std::string>();
    if (j.contains("price")     && j["price"].is_number())     a.price    = j["price"].get<double>();
    return a;
}

struct SearchResult {
    int          count = 0;
    std::vector<App> results;
};

static SearchResult parse_search_json(const std::string& body) {
    SearchResult out;
    try {
        auto j = json::parse(body);
        if (j.contains("resultCount") && j["resultCount"].is_number())
            out.count = j["resultCount"].get<int>();
        if (j.contains("results") && j["results"].is_array())
            for (auto& item : j["results"])
                out.results.push_back(app_from_json(item));
    } catch (...) {}
    return out;
}
