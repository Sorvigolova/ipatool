#include "purchase_flow.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {
int failures = 0;

void expect(bool condition, const char* description) {
    if (condition) return;
    std::cerr << "FAIL: " << description << '\n';
    ++failures;
}

PlistValue downloadable_item() {
    PlistDict sinf;
    sinf["sinf"] = PlistValue::makeData({0x01, 0x02});
    PlistDict item;
    item["sinfs"] = PlistValue::makeArray({PlistValue::makeDict(sinf)});
    return PlistValue::makeDict(item);
}
} // namespace

int main() {
    expect(is_purchase_unavailable_message(
               "Purchase of this item is not currently available."),
           "recognizes Apple's purchase-unavailable response");
    expect(is_purchase_unavailable_message(
               std::string(" PURCHASE") + "\xC2\xA0" + "OF" + "\xC2\xA0"
               + "THIS" + "\xC2\xA0" + "ITEM IS NOT CURRENTLY AVAILABLE "),
           "normalizes non-breaking spaces and case");
    expect(!is_purchase_unavailable_message("This app is no longer available"),
           "does not reinterpret unrelated availability errors");
    expect(is_purchase_unavailable_message("Unable to process your request."),
           "treats Apple's non-actionable purchase dialog as retryable");

    PlistDict freeLicense;
    freeLicense["jingleDocType"] = PlistValue::makeString("purchaseSuccess");
    freeLicense["status"] = PlistValue::makeInt(0);
    expect(is_modern_purchase_success(freeLicense),
           "accepts a valid license receipt with no immediate download item");

    PlistDict downloadResponse;
    downloadResponse["songList"] = PlistValue::makeArray({downloadable_item()});
    expect(is_modern_purchase_success(downloadResponse),
           "accepts a redownload response containing FairPlay data");

    PlistDict failedDownload = downloadResponse;
    failedDownload["failureType"] = PlistValue::makeString("9610");
    expect(!is_modern_purchase_success(failedDownload),
           "does not accept a songList attached to a failed response");
    expect(!is_modern_purchase_success(PlistDict{}),
           "rejects an empty or undecodable HTTP response instead of reporting success");

    PlistDict incompleteItem;
    PlistDict item;
    item["sinfs"] = PlistValue::makeArray({PlistValue::makeDict(PlistDict{})});
    incompleteItem["songList"] = PlistValue::makeArray({PlistValue::makeDict(item)});
    expect(!is_modern_purchase_success(incompleteItem),
           "requires usable FairPlay data for download-only responses");

    if (failures != 0) return EXIT_FAILURE;
    std::cout << "purchase flow tests passed\n";
    return EXIT_SUCCESS;
}
