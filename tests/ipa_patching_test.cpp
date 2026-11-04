#include "appstore.h"

#include <minizip/zip.h>
#include <minizip/unzip.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>

using Bytes = std::vector<uint8_t>;
namespace fs = std::filesystem;

struct AppStoreTestAccess {
    static std::string executable(const Bytes& data) {
        return AppStore::extract_plist_string(data, "CFBundleExecutable");
    }
    static std::vector<std::string> paths(const Bytes& data) {
        return AppStore::extract_sinf_paths(data);
    }
    static void patch(const fs::path& input, const fs::path& output,
                      const std::vector<Sinf>& licenses) {
        AppStore::patch_with_minizip(input.string(), output.string(),
                                    Bytes{'m', 'e', 't', 'a'}, {}, licenses);
    }
};

static void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

static Bytes bytes(const std::string& value) {
    return Bytes(value.begin(), value.end());
}

static Bytes read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.good(), "cannot read fixture: " + path.string());
    return Bytes(std::istreambuf_iterator<char>(input), {});
}

static void write_zip(const fs::path& path,
                      const std::vector<std::pair<std::string, Bytes>>& members) {
    zipFile archive = zipOpen(path.string().c_str(), APPEND_STATUS_CREATE);
    require(archive != nullptr, "cannot create fixture IPA");
    for (const auto& [name, content] : members) {
        zip_fileinfo info{};
        require(zipOpenNewFileInZip(archive, name.c_str(), &info, nullptr, 0,
                                    nullptr, 0, nullptr, Z_DEFLATED, Z_DEFAULT_COMPRESSION) == ZIP_OK,
                "cannot create fixture member");
        require(zipWriteInFileInZip(archive, content.data(), static_cast<unsigned>(content.size())) == ZIP_OK,
                "cannot write fixture member");
        require(zipCloseFileInZip(archive) == ZIP_OK, "cannot close fixture member");
    }
    require(zipClose(archive, nullptr) == ZIP_OK, "cannot close fixture IPA");
}

static std::map<std::string, Bytes> read_zip(const fs::path& path) {
    unzFile archive = unzOpen(path.string().c_str());
    require(archive != nullptr, "cannot read patched IPA");
    std::map<std::string, Bytes> members;
    int status = unzGoToFirstFile(archive);
    while (status == UNZ_OK) {
        char name[1024]{};
        unz_file_info info{};
        require(unzGetCurrentFileInfo(archive, &info, name, sizeof(name), nullptr, 0, nullptr, 0) == UNZ_OK,
                "cannot read patched member info");
        require(unzOpenCurrentFile(archive) == UNZ_OK, "cannot open patched member");
        Bytes content(info.uncompressed_size);
        size_t offset = 0;
        while (offset < content.size()) {
            int count = unzReadCurrentFile(archive, content.data() + offset,
                                          static_cast<unsigned>(content.size() - offset));
            require(count > 0, "cannot read patched member content");
            offset += static_cast<size_t>(count);
        }
        require(unzCloseCurrentFile(archive) == UNZ_OK, "patched member CRC failed");
        require(members.emplace(name, std::move(content)).second, "duplicate patched member");
        status = unzGoToNextFile(archive);
    }
    require(status == UNZ_END_OF_LIST_OF_FILE, "cannot enumerate patched IPA");
    unzClose(archive);
    return members;
}

struct TemporaryDirectory {
    fs::path path;
    TemporaryDirectory() {
        path = fs::temp_directory_path() /
            ("ipatool-ipa-patching-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        require(fs::create_directory(path), "cannot create test directory");
    }
    ~TemporaryDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
    }
};

static void check_patching(const Bytes& info, const Bytes& manifest,
                           const std::string& executable,
                           const std::vector<std::string>& license_paths) {
    TemporaryDirectory temporary;
    const std::string root = "Payload/Test.app/";
    const Bytes code = bytes("synthetic executable; must remain byte-identical");
    const Bytes supplement = bytes("synthetic supplementary data");
    std::vector<std::pair<std::string, Bytes>> members{
        {root + "Info.plist", info}, {root + executable, code},
        {root + "SC_Info/" + executable + ".supp", supplement},
    };
    if (!manifest.empty()) members.emplace_back(root + "SC_Info/Manifest.plist", manifest);
    const auto input = temporary.path / "input.ipa";
    const auto output = temporary.path / "output.ipa";
    write_zip(input, members);
    const auto input_before = read_file(input);
    std::vector<Sinf> licenses(license_paths.size());
    for (size_t i = 0; i < licenses.size(); ++i)
        licenses[i].data = bytes("synthetic license " + std::to_string(i));

    AppStoreTestAccess::patch(input, output, licenses);
    const auto patched = read_zip(output);
    for (const auto& [name, content] : members)
        require(patched.count(name) && patched.at(name) == content, "original member changed: " + name);
    std::set<std::string> expected_licenses;
    for (size_t i = 0; i < license_paths.size(); ++i) {
        const auto name = root + license_paths[i];
        expected_licenses.insert(name);
        require(patched.count(name), "missing expected license: " + name);
        require(patched.at(name) == licenses[i].data, "license associated with wrong path");
    }
    for (const auto& [name, content] : patched) {
        if (name.ends_with(".sinf")) require(expected_licenses.count(name), "unexpected license path: " + name);
    }
    require(patched.at("iTunesMetadata.plist") == Bytes({'m', 'e', 't', 'a'}), "metadata injection failed");
    require(read_file(input) == input_before, "input IPA modified");
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const fs::path fixtures = argv[1];
    const auto binary_info = read_file(fixtures / "Info.binary.plist");
    const auto unicode_info = read_file(fixtures / "Info.unicode.binary.plist");
    const auto binary_manifest = read_file(fixtures / "Manifest.binary.plist");
    const std::vector<std::string> license_paths{
        "SC_Info/PrimaryExecutable.sinf", "PlugIns/Widget.appex/SC_Info/WidgetExecutable.sinf"};
    const auto xml_info = bytes(encode_plist_xml({{"CFBundleExecutable", PlistValue::makeString("LegacyGame")}}));
    const auto xml_manifest = bytes(encode_plist_xml({{"SinfPaths", PlistValue::makeArray({
        PlistValue::makeString(license_paths[0]), PlistValue::makeString(license_paths[1])})}}));
    int failures = 0;
    auto run = [&](const char* label, auto test) {
        try { test(); std::cout << "PASS " << label << '\n'; }
        catch (const std::exception& error) {
            ++failures; std::cerr << "FAIL " << label << ": " << error.what() << '\n';
        }
    };
    run("binary Info.plist fallback", [&] { check_patching(binary_info, {}, "LegacyGame", {"SC_Info/LegacyGame.sinf"}); });
    run("XML Info.plist fallback", [&] { check_patching(xml_info, {}, "LegacyGame", {"SC_Info/LegacyGame.sinf"}); });
    run("binary SinfPaths manifest", [&] { check_patching(xml_info, binary_manifest, "LegacyGame", license_paths); });
    run("XML SinfPaths manifest", [&] { check_patching(xml_info, xml_manifest, "LegacyGame", license_paths); });
    run("binary extended UTF-16 string", [&] {
        require(AppStoreTestAccess::executable(unicode_info) == "\xC3\x89preuve-Executable-Long", "incorrect executable string");
    });
    run("XML escaped executable", [&] {
        const auto info = bytes(encode_plist_xml({{"CFBundleExecutable", PlistValue::makeString("Game & Tools")}}));
        check_patching(info, {}, "Game & Tools", {"SC_Info/Game & Tools.sinf"});
    });
    run("missing and wrong-type keys", [&] {
        require(AppStoreTestAccess::executable(bytes(encode_plist_xml({}))).empty(), "missing executable key");
        require(AppStoreTestAccess::executable(bytes(encode_plist_xml({{"CFBundleExecutable", PlistValue::makeInt(7)}}))).empty(), "wrong executable type");
        require(AppStoreTestAccess::paths(bytes(encode_plist_xml({{"SinfPaths", PlistValue::makeString("not an array")}}))).empty(), "wrong SinfPaths type");
    });
    return failures ? 1 : 0;
}
