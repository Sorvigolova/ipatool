#include "store_adi.h"

// Android ADI symbols and guest ABI reference: Anisette.py (MIT License),
// Copyright (c) 2025 Anisette.py Contributors.

#include "http_client.h"
#include "ipatool.h"
#include "path_utf8.h"
#include "plist.h"
#include "SapSigner.h"
#include "sha2.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <random>
#include <span>
#include <unicorn/unicorn.h>
#include <unicorn/arm64.h>
#include <zlib.h>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace ipt {

namespace {

constexpr const char* apk_url = "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk";
constexpr const char* finish_url = "https://auth.itunes.apple.com/auth/v1/otp/1.5/finish";
constexpr const char* store_agent =
    "Configurator/2.21 (Macintosh; OS X 15.7; 24G222) AppleWebKit/0620.2.4.11.6";
constexpr std::array library_names{"libstoreservicescore.so", "libCoreADI.so"};
constexpr std::array library_hashes{
    "bd335e6963ba5ae2f5babca613435ad56d2660a9aee37df35f876c458d105ce4",
    "9d5b557cf3faf88c34c394ab2cd7fc1a3b4acf3aed51f28cd0bc093858107c22"};
constexpr uint64_t scope = UINT64_MAX;
constexpr size_t max_state = 64 * 1024;
constexpr size_t max_library = 16 * 1024 * 1024;

std::string hex(std::span<const uint8_t> bytes) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string text;
    for (const auto byte : bytes) {
        text += digits[byte >> 4];
        text += digits[byte & 15];
    }
    return text;
}

std::filesystem::path state_directory() {
#ifdef _WIN32
    if (const auto* home = _wgetenv(L"USERPROFILE"); home && *home)
        return std::filesystem::path(home) / ".ipatool" / "store-proof";
#else
    if (const auto* home = std::getenv("HOME"); home && *home)
        return std::filesystem::path(home) / ".ipatool" / "store-proof";
#endif
    throw IpaError("could not locate the Store AMD state directory");
}

class StateLock {
public:
    explicit StateLock(const std::filesystem::path& path) {
#ifdef _WIN32
        handle_ = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle_ != INVALID_HANDLE_VALUE && LockFileEx(handle_, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &lock_))
            return;
        if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
#else
        fd_ = open(path.c_str(), O_CREAT | O_CLOEXEC | O_RDWR, 0600);
        if (fd_ >= 0 && flock(fd_, LOCK_EX) == 0) return;
        if (fd_ >= 0) close(fd_);
#endif
        throw IpaError("could not lock the Store AMD state");
    }
    ~StateLock() {
#ifdef _WIN32
        UnlockFileEx(handle_, 0, 1, 0, &lock_);
        CloseHandle(handle_);
#else
        close(fd_);
#endif
    }
    StateLock(const StateLock&) = delete;
    StateLock& operator=(const StateLock&) = delete;
private:
#ifdef _WIN32
    HANDLE handle_;
    OVERLAPPED lock_{};
#else
    int fd_;
#endif
};

std::string read_file(const std::filesystem::path& path, size_t limit) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    const auto length = file.tellg();
    if (length < 0 || static_cast<uint64_t>(length) > limit) return {};
    std::string data(static_cast<size_t>(length), '\0');
    file.seekg(0);
    return file.read(data.data(), data.size()) ? std::move(data) : std::string{};
}

void save_file(const std::filesystem::path& path, std::string_view data) {
    auto temporary = path;
    temporary += ".tmp";
    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        file.write(data.data(), data.size());
        file.close();
        if (!file) throw IpaError("could not write Store AMD state");
    }
#ifdef _WIN32
    if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw IpaError("could not replace Store AMD state");
#else
    std::filesystem::permissions(temporary, std::filesystem::perms::owner_read |
        std::filesystem::perms::owner_write, std::filesystem::perm_options::replace);
    std::filesystem::rename(temporary, path);
#endif
}

std::string_view c_field(std::string_view field) {
    return field.substr(0, field.find('\0'));
}

struct DeviceState {
    std::string identifier;
    std::string adi;
    std::array<std::string, 2> libraries;
};

// The previous helper wrote a gzip-compressed tar archive named state.zip.
// Read only the known entries, without extracting any paths from the archive.
DeviceState read_legacy(const std::filesystem::path& path) {
    DeviceState state;
#ifdef _WIN32
    auto raw = gzopen_w(path.c_str(), "rb");
#else
    auto raw = gzopen(path.c_str(), "rb");
#endif
    if (!raw) return state;
    std::unique_ptr<gzFile_s, decltype(&gzclose)> file(raw, gzclose);
    size_t total = 0;
    std::array<char, 512> header{};
    while (gzread(file.get(), header.data(), header.size()) == header.size() && header[0]) {
        auto name = c_field(std::string_view(header.data(), 100));
        if (name.starts_with("./")) name.remove_prefix(2);
        size_t size = 0;
        const auto length = c_field(std::string_view(header.data() + 124, 12));
        if (std::from_chars(length.data(), length.data() + length.size(), size, 8).ec != std::errc{} ||
            size > max_library || (total += size + 512) > 2 * max_library) return {};
        std::string data((size + 511) / 512 * 512, '\0');
        if (!data.empty() && gzread(file.get(), data.data(), static_cast<unsigned>(data.size())) != data.size())
            return {};
        data.resize(size);
        if (name == "device/device.json") {
            auto json = nlohmann::json::parse(data, nullptr, false);
            if (json.is_object() && json.contains("identifier") && json["identifier"].is_string())
                state.identifier = json["identifier"].get<std::string>();
        } else if (name == "adi/adi.pb" && size <= max_state) {
            state.adi = std::move(data);
        } else if (name == "libs/libstoreservicescore.so") {
            state.libraries[0] = std::move(data);
        } else if (name == "libs/libCoreADI.so") {
            state.libraries[1] = std::move(data);
        }
    }
    return state;
}

bool is_hex(std::string_view value, size_t length) {
    return value.size() == length && value.find_first_not_of("0123456789abcdefABCDEF") == value.npos;
}

uint64_t number(std::string_view bytes, uint64_t offset, unsigned width) {
    if (offset > bytes.size() || width > bytes.size() - offset)
        throw IpaError("truncated Store ADI image");
    uint64_t result = 0;
    for (unsigned i = 0; i < width; ++i)
        result |= uint64_t(static_cast<unsigned char>(bytes[offset + i])) << (8 * i);
    return result;
}

class AdiMachine {
public:
    explicit AdiMachine(const DeviceState& state) : state_(state), adi_(state.adi) {
        uc_engine* raw = nullptr;
        check(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &raw));
        engine_.reset(raw);
        map(stack_, stack_size_);
        map(heap_, heap_size_);
        map(scratch_, 0x10000);
        map(imports_, 0x20000);
        map(return_, 0x1000);
        std::vector<uint32_t> returns(0x20000 / 4, 0xd65f03c0);
        check(uc_mem_write(engine_.get(), imports_, returns.data(), returns.size() * sizeof(uint32_t)));
        uc_hook handle{};
        check(uc_hook_add(engine_.get(), &handle, UC_HOOK_CODE,
                          reinterpret_cast<void*>(&on_import), this, imports_, imports_ + 0x1ffff));
        load_library(0);
        const auto identifier = place(state.identifier);
        const auto dot = place(".");
        expect(call("Sph98paBcz", {identifier, state.identifier.size()}), "setting device identifier");
        expect(call("nf92ngaK92", {dot}), "setting device state path");
        expect(call("kq56gsgHG6", {dot}), "loading CoreADI");
    }

    bool ready() {
        const auto result = call("aslgmuibau", {scope});
        if (result == -45061) return false;
        expect(result, "checking device registration");
        return true;
    }

    std::string begin(std::span<const uint8_t> challenge) {
        const auto data = place({reinterpret_cast<const char*>(challenge.data()), challenge.size()});
        const auto output = place(std::string(24, '\0'));
        expect(call("rsegvyrt87", {scope, data, challenge.size(), output, output + 8, output + 16}),
               "starting device registration");
        session_ = read<uint32_t>(output + 16);
        return take(output, output + 8);
    }

    void finish(std::span<const uint8_t> setting, std::span<const uint8_t> transport) {
        const auto a = place({reinterpret_cast<const char*>(setting.data()), setting.size()});
        const auto b = place({reinterpret_cast<const char*>(transport.data()), transport.size()});
        expect(call("uv5t6nhkui", {session_, a, setting.size(), b, transport.size()}),
               "finishing device registration");
    }

    std::map<std::string, std::string> headers() {
        const auto output = place(std::string(32, '\0'));
        expect(call("qi864985u0", {scope, output, output + 8, output + 16, output + 24}),
               "creating device proof");
        const auto mid = take(output, output + 8);
        const auto otp = take(output + 16, output + 24);
        return {{"X-Apple-AMD", encode(otp)}, {"X-Apple-AMD-M", encode(mid)}};
    }

    const std::string& adi_state() const { return adi_; }

    static std::string encode(std::string_view data) {
        return SapBase64::Encode({reinterpret_cast<const uint8_t*>(data.data()), data.size()});
    }

private:
    static constexpr uint64_t stack_ = 0x70000000, stack_size_ = 0x100000;
    static constexpr uint64_t heap_ = 0x60000000, heap_size_ = 0x2000000;
    static constexpr uint64_t scratch_ = 0x80000000;
    static constexpr uint64_t imports_ = 0x50000000, return_ = 0x51000000;
    const DeviceState& state_;
    std::string adi_;
    std::unique_ptr<uc_engine, decltype(&uc_close)> engine_{nullptr, uc_close};
    std::array<std::map<std::string, uint64_t>, 2> symbols_;
    std::map<uint64_t, std::string> hooks_;
    std::map<uint64_t, size_t> offsets_;
    uint64_t next_fd_ = 3, heap_next_ = heap_, scratch_next_ = scratch_ + 16;
    uint32_t session_ = 0;
    std::string hook_error_;
    std::random_device random_;

    static void check(uc_err error) {
        if (error != UC_ERR_OK) throw IpaError(std::string("Store ADI emulator: ") + uc_strerror(error));
    }
    static void expect(int result, const char* operation) {
        if (result) throw IpaError(std::string("Store ADI failed while ") + operation +
                                  " (" + std::to_string(result) + ")");
    }
    void map(uint64_t address, size_t size) {
        check(uc_mem_map(engine_.get(), address, size, UC_PROT_ALL));
    }
    void write(uint64_t address, std::string_view data) {
        if (!data.empty()) check(uc_mem_write(engine_.get(), address, data.data(), data.size()));
    }
    template<class T> void write(uint64_t address, T value) {
        check(uc_mem_write(engine_.get(), address, &value, sizeof(value)));
    }
    template<class T> T read(uint64_t address) {
        T value{};
        check(uc_mem_read(engine_.get(), address, &value, sizeof(value)));
        return value;
    }
    std::string read_bytes(uint64_t address, size_t size) {
        if (size > max_state) throw IpaError("oversize Store ADI buffer");
        std::string data(size, '\0');
        if (size) check(uc_mem_read(engine_.get(), address, data.data(), size));
        return data;
    }
    std::string guest_string(uint64_t address) {
        std::string data;
        for (size_t i = 0; i < 1024; ++i) {
            const auto ch = read<char>(address + i);
            if (!ch) return data;
            data += ch;
        }
        throw IpaError("unterminated Store ADI string");
    }
    uint64_t place(std::string_view data) {
        const auto addr = scratch_next_;
        scratch_next_ += (data.size() + 16) & ~size_t(15);
        if (scratch_next_ > scratch_ + 0x10000) throw IpaError("Store ADI scratch space exhausted");
        write(addr, data);
        write<uint8_t>(addr + data.size(), 0);
        return addr;
    }
    uint64_t reg(int name) {
        uint64_t value{};
        check(uc_reg_read(engine_.get(), name, &value));
        return value;
    }
    void set_reg(int name, uint64_t value) {
        check(uc_reg_write(engine_.get(), name, &value));
    }
    int call(const std::string& name, std::initializer_list<uint64_t> args) {
        int index = UC_ARM64_REG_X0;
        for (const auto value : args) set_reg(index++, value);
        set_reg(UC_ARM64_REG_SP, stack_ + stack_size_);
        set_reg(UC_ARM64_REG_LR, return_);
        const auto result = uc_emu_start(engine_.get(), symbols_[0].at(name), return_, 8000000, 100000000);
        if (!hook_error_.empty()) throw IpaError(hook_error_);
        check(result);
        if (reg(UC_ARM64_REG_PC) != return_) throw IpaError("Store ADI emulation timed out");
        return static_cast<int32_t>(reg(UC_ARM64_REG_X0));
    }
    std::string take(uint64_t pointer, uint64_t length) {
        const auto address = read<uint64_t>(pointer);
        const auto size = read<uint32_t>(length);
        if (!address || !size || size > 4096) throw IpaError("invalid Store ADI output");
        auto data = read_bytes(address, size);
        call("jk24uiwqrg", {address});
        return data;
    }

    void load_library(size_t index) {
        if (!symbols_[index].empty()) return;
        const std::string_view elf = state_.libraries[index];
        if (!elf.starts_with("\x7f" "ELF\x02\x01") || number(elf, 18, 2) != 183)
            throw IpaError("invalid ARM64 Store ADI image");
        const auto base = 0x10000000ull + index * 0x10000000ull;
        const auto programs = number(elf, 32, 8);
        const auto program_size = number(elf, 54, 2);
        const auto program_count = number(elf, 56, 2);
        uint64_t image_size = 0;
        for (uint64_t i = 0; i < program_count; ++i) {
            const auto p = programs + i * program_size;
            if (number(elf, p, 4) != 1) continue;
            image_size = std::max(image_size, number(elf, p + 16, 8) + number(elf, p + 40, 8));
        }
        if (!image_size || image_size > 64 * 1024 * 1024) throw IpaError("invalid Store ADI image size");
        map(base, (image_size + 4095) & ~uint64_t(4095));
        for (uint64_t i = 0; i < program_count; ++i) {
            const auto p = programs + i * program_size;
            if (number(elf, p, 4) != 1) continue;
            const auto offset = number(elf, p + 8, 8), size = number(elf, p + 32, 8);
            if (offset > elf.size() || size > elf.size() - offset)
                throw IpaError("truncated Store ADI segment");
            write(base + number(elf, p + 16, 8), elf.substr(offset, size));
        }
        const auto sections = number(elf, 40, 8);
        const auto section_size = number(elf, 58, 2);
        const auto section_count = number(elf, 60, 2);
        std::vector<uint64_t> values;
        for (uint64_t i = 0; i < section_count; ++i) {
            const auto p = sections + i * section_size;
            if (number(elf, p + 4, 4) != 11) continue;
            const auto offset = number(elf, p + 24, 8), size = number(elf, p + 32, 8);
            const auto names = sections + number(elf, p + 40, 4) * section_size;
            const auto strings = elf.substr(number(elf, names + 24, 8), number(elf, names + 32, 8));
            for (uint64_t j = 0; j + 24 <= size; j += 24) {
                const auto sym = offset + j;
                const auto name = c_field(strings.substr(number(elf, sym, 4)));
                if (number(elf, sym + 6, 2) == 0) {
                    const auto addr = imports_ + index * 0x10000 + values.size() * 4;
                    if (values.size() >= 0x4000) throw IpaError("too many Store ADI imports");
                    hooks_.emplace(addr, name);
                    values.push_back(addr);
                } else {
                    const auto addr = base + number(elf, sym + 8, 8);
                    symbols_[index].emplace(name, addr);
                    values.push_back(addr);
                }
            }
            break;
        }
        for (uint64_t i = 0; i < section_count; ++i) {
            const auto p = sections + i * section_size;
            if (number(elf, p + 4, 4) != 4) continue;
            const auto offset = number(elf, p + 24, 8), size = number(elf, p + 32, 8);
            for (uint64_t j = 0; j + 24 <= size; j += 24) {
                const auto r = offset + j;
                const auto info = number(elf, r + 8, 8), addend = number(elf, r + 16, 8);
                const auto type = static_cast<uint32_t>(info);
                uint64_t value = 0;
                if (type == 1027) value = base + addend;
                else if (type == 257 || type == 1025 || type == 1026)
                    value = values.at(info >> 32) + (type == 1026 ? 0 : addend);
                else throw IpaError("unsupported Store ADI relocation " + std::to_string(type));
                write<uint64_t>(base + number(elf, r, 8), value);
            }
        }
    }

    static void on_import(uc_engine* engine, uint64_t address, uint32_t, void* data) {
        auto& machine = *static_cast<AdiMachine*>(data);
        try {
            machine.set_reg(UC_ARM64_REG_X0, machine.import(machine.hooks_.at(address)));
        } catch (const std::exception& error) {
            machine.hook_error_ = error.what();
            uc_emu_stop(engine);
        }
    }
    uint64_t error(int value) {
        write<uint32_t>(scratch_, value);
        return UINT64_MAX;
    }
    uint64_t stat(uint64_t destination, bool directory) {
        write(destination, std::string_view(std::string(128, '\0')));
        write<uint32_t>(destination + 16, directory ? 040700 : 0100600);
        write<uint64_t>(destination + 48, directory ? 0 : adi_.size());
        write<uint64_t>(destination + 88, std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
        return 0;
    }
    uint64_t import(const std::string& name) {
        const auto a = reg(UC_ARM64_REG_X0), b = reg(UC_ARM64_REG_X1), c = reg(UC_ARM64_REG_X2);
        if (name == "malloc") {
            if (a > heap_size_ || heap_next_ + a + 16 > heap_ + heap_size_) return 0;
            const auto address = heap_next_;
            heap_next_ += (a + 16) & ~uint64_t(15);
            return address;
        }
        if (name == "free" || name == "dlclose" || name == "umask" || name == "chmod"
            || name == "mkdir" || name.starts_with("pthread_")) return 0;
        if (name == "dlopen") {
            if (!guest_string(a).ends_with("/libCoreADI.so")) return 0;
            load_library(1);
            return 2;
        }
        if (name == "dlsym") {
            if (a != 2) return 0;
            const auto found = symbols_[1].find(guest_string(b));
            return found == symbols_[1].end() ? 0 : found->second;
        }
        if (name == "strncpy") {
            if (c > max_state) throw IpaError("oversize Store ADI string");
            auto value = guest_string(b);
            value.resize(c, '\0');
            write(a, std::string_view(value));
            return a;
        }
        if (name == "__errno") return scratch_;
        if (name == "__system_property_get") {
            constexpr char value[] = "no s/n number";
            write(b, std::string_view(value, sizeof(value)));
            return sizeof(value) - 1;
        }
        if (name == "arc4random") return random_();
        if (name == "gettimeofday") {
            const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            write<int64_t>(a, micros / 1000000);
            write<int64_t>(a + 8, micros % 1000000);
            return 0;
        }
        if (name == "lstat" || name == "open") {
            auto path = guest_string(a);
            if (name == "lstat" && (path == "." || path == "./")) return stat(b, true);
            if (path != "adi.pb" && path != "./adi.pb") return error(2);
            if (name == "lstat") return adi_.empty() ? error(2) : stat(b, false);
            if (b & 0x200) adi_.clear(); // O_TRUNC
            if (adi_.empty() && (b & 0x40) == 0 && (b & 3) == 0) return error(2);
            const auto descriptor = next_fd_++;
            offsets_.emplace(descriptor, 0);
            return descriptor;
        }
        if (name == "fstat" || name == "close" || name == "read" || name == "write" || name == "ftruncate") {
            const auto file = offsets_.find(a);
            if (file == offsets_.end()) return error(9);
            auto& offset = file->second;
            if (name == "fstat") return stat(b, false);
            if (name == "close") { offsets_.erase(file); return 0; }
            if (name == "ftruncate") {
                if (b > max_state) return error(27);
                adi_.resize(b);
                return 0;
            }
            if (name == "read") {
                const auto count = offset < adi_.size() ? std::min<uint64_t>(c, adi_.size() - offset) : 0;
                if (count) write(b, std::string_view(adi_).substr(offset, count));
                offset += count;
                return count;
            }
            if (offset > max_state || c > max_state - offset) return error(27);
            if (offset + c > adi_.size()) adi_.resize(offset + c);
            adi_.replace(offset, c, read_bytes(b, c));
            offset += c;
            return c;
        }
        throw IpaError("unsupported Store ADI import " + name);
    }
};

} // namespace

std::map<std::string, std::string> store_proof_headers(const std::string& challenge, const std::string& guid) {
    const auto dir = state_directory();
    const bool created = std::filesystem::create_directories(dir);
#ifndef _WIN32
    if (created) std::filesystem::permissions(dir, std::filesystem::perms::owner_all);
#else
    (void)created;
#endif
    const StateLock lock(dir / "native.lock");
    DeviceState state;
    const auto native_path = dir / "native-state";
    const auto saved = read_file(native_path, 16 + max_state);
    if (saved.size() > 16 && is_hex(std::string_view(saved).substr(0, 16), 16)) {
        state.identifier = saved.substr(0, 16);
        state.adi = saved.substr(16);
    } else {
        state = read_legacy(dir / "state.zip");
    }
    if (challenge.empty() && (!is_hex(state.identifier, 16) || state.adi.empty())) return {};
    if (!is_hex(state.identifier, 16)) {
        std::random_device random;
        std::array<uint8_t, 8> bytes{};
        for (auto& byte : bytes) byte = static_cast<uint8_t>(random());
        state.identifier = hex(bytes);
    }
    HttpClient http("");
    for (size_t i = 0; i < library_names.size(); ++i) {
        const auto path = dir / library_names[i];
        auto& library = state.libraries[i];
        if (library.empty()) library = read_file(path, max_library);
        if (hex(sha2::digest(library)) != library_hashes[i]) {
            if (!fetch_remote_zip_entry(http, apk_url, std::string("lib/arm64-v8a/") + library_names[i], library)
                || hex(sha2::digest(library)) != library_hashes[i])
                throw IpaError("could not download a verified Store ADI library from Apple");
            save_file(path, library);
        } else if (!std::filesystem::exists(path)) {
            save_file(path, library);
        }
    }
    AdiMachine machine(state);
    if (!challenge.empty()) {
        const auto bytes = SapBase64::Decode(challenge);
        if (!is_hex(guid, 12) || bytes.empty() || bytes.size() > 4096)
            throw IpaError("invalid Store AMD provisioning challenge");
        const auto client = machine.begin(bytes);
        const auto response = http.post(finish_url, encode_plist_xml({
            {"clientData", PlistValue::makeString(AdiMachine::encode(client))},
            {"guid", PlistValue::makeString(guid)}}),
            {{"User-Agent", store_agent}, {"Content-Type", "application/x-apple-plist"}});
        if (response.statusCode != 200 || response.body.size() > (1 << 20))
            throw IpaError("Store AMD provisioning returned HTTP " + std::to_string(response.statusCode));
        const auto data = decode_plist(response.body);
        const auto setting = SapBase64::Decode(dict_str(data, "settingInfo"));
        const auto transport = SapBase64::Decode(dict_str(data, "transportKey"));
        if (setting.empty() || transport.empty()) throw IpaError("incomplete Store AMD provisioning response");
        machine.finish(setting, transport);
    }
    if (!machine.ready()) return {};
    const auto headers = machine.headers();
    const auto current = state.identifier + machine.adi_state();
    if (current != saved) save_file(native_path, current);
    return headers;
}

} // namespace ipt
