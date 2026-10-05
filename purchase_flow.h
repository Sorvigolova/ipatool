#pragma once

#include "plist.h"
#include <string>

// Normalize Apple purchase status responses without coupling these protocol
// decisions to HTTP or download orchestration.
std::string normalize_apple_text(const std::string& message);
bool is_purchase_unavailable_message(const std::string& message);
bool is_modern_purchase_success(const PlistDict& response);
