#pragma once
// GCC < 13 and some other compilers ship <format> as an incomplete stub.
// __cpp_lib_format is only defined when the implementation is actually complete.
// Use fmtlib as a drop-in replacement when std::format is unavailable.
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
