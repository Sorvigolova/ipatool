#pragma once
// Cross-platform UTF-8 path handling.
//
// Inside the program every path is a UTF-8 std::string. On POSIX that is also
// the native filesystem encoding, so paths pass straight through. On Windows the
// narrow CRT (fopen, std::fstream built from a std::string, std::filesystem::path
// built from a std::string) interprets narrow paths in the *active ANSI code
// page*, not UTF-8 — so any non-ASCII path (e.g. Cyrillic "D:\Даунлоадер\...")
// fails to open. These helpers convert UTF-8 → UTF-16 and use the wide APIs.
//
//   ipt::fs_path(utf8)        → std::filesystem::path for fs:: ops and fstreams
//   ipt::fopen_utf8(path,mode)→ FILE* (uses _wfopen on Windows)
//   ipt::utf8_to_wide(utf8)   → std::wstring (Windows only; for minizip iowin32)

#include <string>
#include <filesystem>
#include <cstdio>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace ipt {

#if defined(_WIN32)

inline std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

inline std::filesystem::path fs_path(const std::string& utf8) {
    return std::filesystem::path(utf8_to_wide(utf8));
}

inline FILE* fopen_utf8(const std::string& path, const char* mode) {
    std::wstring wmode;
    for (const char* p = mode; *p; ++p) wmode.push_back(static_cast<wchar_t>(*p));
    return _wfopen(utf8_to_wide(path).c_str(), wmode.c_str());
}

// UTF-16 → UTF-8.
inline std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        s.data(), n, nullptr, nullptr);
    return s;
}

// Convert a filesystem path back to UTF-8 (path::string() would return the
// active ANSI code page on Windows, re-mangling non-ASCII).
inline std::string to_utf8(const std::filesystem::path& p) {
    return wide_to_utf8(p.wstring());
}

#else  // POSIX — UTF-8 is the native encoding

inline std::filesystem::path fs_path(const std::string& utf8) {
    return std::filesystem::path(utf8);
}

inline FILE* fopen_utf8(const std::string& path, const char* mode) {
    return std::fopen(path.c_str(), mode);
}

inline std::string to_utf8(const std::filesystem::path& p) {
    return p.string();
}

#endif

}  // namespace ipt
