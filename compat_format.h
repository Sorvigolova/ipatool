#pragma once
// GCC < 13 and some other compilers ship <format> as an incomplete stub.
// __cpp_lib_format is only defined when the implementation is actually complete.
// Use fmtlib as a drop-in replacement when std::format is unavailable.
//
// <version> must be included first: the library feature-test macro
// __cpp_lib_format is defined by <version> (or <format>), not by the language.
// Without this include the macro may still be undefined at the check below
// (e.g. libstdc++ 13 when only <algorithm>/<cstring> were included before us),
// wrongly selecting the fmt path while CMake links only real std::format.
#include <version>
#if defined(__cpp_lib_format)
#  include <format>
#else
#  include <fmt/format.h>
   // Inject into std:: so all std::format() calls work unchanged
   namespace std {
       using fmt::format;
       using fmt::vformat;
   }
#endif
