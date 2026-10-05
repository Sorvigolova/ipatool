#include "purchase_flow.h"

#include <algorithm>
#include <cctype>

PurchaseProtocol preferred_purchase_protocol(const App& app, bool hasKbsync) {
    return hasKbsync && app.price > 0.0
        ? PurchaseProtocol::ModernMZBuy
        : PurchaseProtocol::LegacyFinance;
}

std::string normalize_apple_text(const std::string& input) {
    std::string out;
    bool pendingSpace = false;

    for (size_t i = 0; i < input.size();) {
        const auto c = static_cast<unsigned char>(input[i]);
        size_t length = 0;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            length = 1;
        } else if (c == 0xC2 && i + 1 < input.size()
                   && static_cast<unsigned char>(input[i + 1]) == 0xA0) {
            length = 2; // NO-BREAK SPACE
        } else if (c == 0xE2 && i + 2 < input.size()
                   && static_cast<unsigned char>(input[i + 1]) == 0x80) {
            const auto third = static_cast<unsigned char>(input[i + 2]);
            if ((third >= 0x80 && third <= 0x8A) || third == 0xAF)
                length = 3; // Unicode typographic spaces
        }

        if (length != 0) {
            pendingSpace = !out.empty();
            i += length;
            continue;
        }
        if (pendingSpace) out.push_back(' ');
        pendingSpace = false;
        out.push_back(input[i++]);
    }
    return out;
}

namespace {
bool has_downloadable_sinfs(const PlistDict& response) {
    const auto songList = dict_arr(response, "songList");
    if (songList.empty() || !songList.front().isDict()) return false;

    const auto sinfs = songList.front().dictVal.find("sinfs");
    if (sinfs == songList.front().dictVal.end() || !sinfs->second.isArray()) return false;
    for (const auto& item : sinfs->second.arrayVal) {
        if (!item.isDict()) continue;
        for (const char* key : {"sinf", "dpInfo"}) {
            const auto field = item.dictVal.find(key);
            if (field != item.dictVal.end() && field->second.isData()
                && !field->second.dataVal.empty())
                return true;
        }
    }
    return false;
}
} // namespace

bool is_purchase_unavailable_message(const std::string& message) {
    std::string normalized = normalize_apple_text(message);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return normalized.find("purchase of this item is not currently available") != std::string::npos
        || normalized.find("this item is not currently available for purchase") != std::string::npos
        || normalized == "unable to process your request.";
}

bool is_modern_purchase_success(const PlistDict& response) {
    if (!dict_str(response, "failureType").empty()) return false;
    if (has_downloadable_sinfs(response)) return true;
    return dict_str(response, "jingleDocType") == "purchaseSuccess"
        && dict_int(response, "status") == 0;
}
