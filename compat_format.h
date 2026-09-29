#pragma once
// Minimal, dependency-free text formatting used across the project.
//
// The project formats strings only for diagnostics and exception messages
// (never for target/stdout output), and only two placeholder forms are ever
// used: "{}" and "{:#x}". So instead of dragging in std::format (which on Apple
// is availability-gated to macOS 13.3 and is pulled in transitively by
// <chrono>) or an external {fmt} dependency, we implement exactly those two.
//
// Supported syntax:
//   {}      default: strings verbatim, integers as decimal
//   {:#x}   integer as lowercase hex with 0x prefix (":x" / "#x" accepted too)
//   {{ }}   literal braces
// A missing argument renders as "{?}"; an unmatched '{' dumps the remainder.
// No compile-time format checking — acceptable for static diagnostic strings.

#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <cstdio>

namespace ipt {
namespace detail {

struct Arg {
    std::string        dec;              // rendering for "{}"
    bool               integral = false;
    unsigned long long hexval   = 0;     // rendering source for "{:#x}"
};

inline Arg make_arg(const char* s) {
    Arg a; a.dec = s ? s : "(null)"; return a;
}
inline Arg make_arg(char* s)              { return make_arg(static_cast<const char*>(s)); }
inline Arg make_arg(const std::string& s) { Arg a; a.dec = s; return a; }
inline Arg make_arg(std::string_view s)   { Arg a; a.dec = std::string(s); return a; }

template <class T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
inline Arg make_arg(T v) {
    Arg a;
    a.integral = true;
    if constexpr (std::is_signed_v<T>) a.dec = std::to_string(static_cast<long long>(v));
    else                               a.dec = std::to_string(static_cast<unsigned long long>(v));
    // Cast through the value's own unsigned width first to avoid sign-extension.
    a.hexval = static_cast<unsigned long long>(static_cast<std::make_unsigned_t<T>>(v));
    return a;
}

template <class T, std::enable_if_t<std::is_enum_v<T>, int> = 0>
inline Arg make_arg(T v) {
    return make_arg(static_cast<std::underlying_type_t<T>>(v));
}

inline std::string vformat_impl(std::string_view fmt, const Arg* args, std::size_t n) {
    std::string out;
    out.reserve(fmt.size() + 16);
    std::size_t ai = 0;
    for (std::size_t i = 0; i < fmt.size(); ++i) {
        char c = fmt[i];
        if (c == '{') {
            if (i + 1 < fmt.size() && fmt[i + 1] == '{') { out.push_back('{'); ++i; continue; }
            std::size_t j = fmt.find('}', i + 1);
            if (j == std::string_view::npos) { out.append(fmt.substr(i)); break; }
            std::string_view spec = fmt.substr(i + 1, j - (i + 1));  // "" or ":#x"
            const Arg* a = (ai < n) ? &args[ai] : nullptr;
            ++ai;
            if (!a) {
                out.append("{?}");
            } else if ((spec == ":#x" || spec == ":x" || spec == "#x") && a->integral) {
                char buf[24];
                std::snprintf(buf, sizeof buf, "0x%llx", a->hexval);
                out.append(buf);
            } else {
                out.append(a->dec);
            }
            i = j;
        } else if (c == '}' && i + 1 < fmt.size() && fmt[i + 1] == '}') {
            out.push_back('}'); ++i;
        } else {
            out.push_back(c);
        }
    }
    return out;
}

}  // namespace detail

inline std::string format(std::string_view fmt) {
    return detail::vformat_impl(fmt, nullptr, 0);
}

template <class First, class... Rest>
inline std::string format(std::string_view fmt, First&& first, Rest&&... rest) {
    detail::Arg args[] = {
        detail::make_arg(std::forward<First>(first)),
        detail::make_arg(std::forward<Rest>(rest))...
    };
    return detail::vformat_impl(fmt, args, 1 + sizeof...(Rest));
}

}  // namespace ipt
