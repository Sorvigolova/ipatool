#pragma once

#include "ipatool.h"
#include "plist.h"
#include <string>

enum class PurchaseProtocol { LegacyFinance, ModernMZBuy };

// Free-app metadata must keep using the legacy Finance purchase request. The
// modern MZBuy request is for paid/family-shared entitlements; callers with
// incomplete metadata may still try the legacy path first and fall back.
PurchaseProtocol preferred_purchase_protocol(const App& app, bool hasKbsync);

// Normalize Apple purchase status responses without coupling these protocol
// decisions to HTTP or download orchestration.
std::string normalize_apple_text(const std::string& message);
bool is_purchase_unavailable_message(const std::string& message);
bool is_modern_purchase_success(const PlistDict& response);
