cmake_minimum_required(VERSION 3.20)

# ── Static linking option (must be before project() for MSVC CRT selection) ───
option(STATIC_BUILD "Build a static binary (Linux, macOS, and Windows)" OFF)

if(STATIC_BUILD AND WIN32)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING "")
    message(STATUS "MSVC static CRT (MultiThreaded /MT) selected")
    # Must be set before find_package so vcpkg resolves static libraries
    if(NOT DEFINED VCPKG_TARGET_TRIPLET)
        set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "vcpkg triplet")
        message(STATUS "vcpkg triplet set to x64-windows-static")
    endif()
endif()

project(ipatool VERSION 1.0 LANGUAGES CXX)

include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MinGW (Ninja/Makefiles) needs the RC language enabled explicitly to compile
# sap_resources.rc via windres; the VS generator handles .rc on its own.
if(MINGW)
    enable_language(RC)
endif()

if(STATIC_BUILD AND NOT WIN32)
    message(STATUS "Static build enabled — will build curl from source")
    set(BUILD_SHARED_LIBS OFF)

    include(ExternalProject)

    if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24")
        set(_ep_timestamp_opt DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    else()
        set(_ep_timestamp_opt "")
    endif()

    # curl's configure gets --with-openssl. On Linux, bare --with-openssl
    # auto-detects the system -dev package fine. On macOS we build OpenSSL from
    # source (below) and point curl at that same build.
    set(_curl_openssl_flag --with-openssl)

    if(APPLE)
        # ── OpenSSL from source (macOS static) ───────────────────────────────
        # Homebrew's openssl@3 bottle is compiled for the build machine's macOS,
        # so linking it into an older -mmacosx-version-min target yields
        # "object file was built for newer macOS version" warnings and an
        # unclean minos. Build OpenSSL ourselves for the exact arch + deployment
        # target, then feed that build to curl's configure AND to the final link
        # — self-contained, no Homebrew openssl needed. Override the version with
        # -DOPENSSL_VERSION=<x.y.z> if the default 404s or you want a newer one.
        set(OPENSSL_VERSION "3.5.7" CACHE STRING
            "OpenSSL version to build from source for the macOS static build")

        if(CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
            set(_ossl_target darwin64-arm64-cc)
        elseif(CMAKE_OSX_ARCHITECTURES STREQUAL "x86_64")
            set(_ossl_target darwin64-x86_64-cc)
        elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "arm64")
            set(_ossl_target darwin64-arm64-cc)
        else()
            set(_ossl_target darwin64-x86_64-cc)
        endif()

        # OpenSSL's Configure appends trailing tokens as extra compiler flags, so
        # -mmacosx-version-min lands on every .o exactly like it does for curl.
        set(_ossl_extra_flags "")
        if(DEFINED CMAKE_OSX_DEPLOYMENT_TARGET AND CMAKE_OSX_DEPLOYMENT_TARGET)
            set(_ossl_extra_flags -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET})
        endif()

        message(STATUS "Static build will compile OpenSSL ${OPENSSL_VERSION} (${_ossl_target}) from source")
        ExternalProject_Add(openssl_static
            URL https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz
            ${_ep_timestamp_opt}
            CONFIGURE_COMMAND
                <SOURCE_DIR>/Configure ${_ossl_target}
                    no-shared no-tests
                    --prefix=<INSTALL_DIR>
                    --openssldir=<INSTALL_DIR>/ssl
                    --libdir=lib
                    ${_ossl_extra_flags}
            BUILD_COMMAND   $(MAKE)
            INSTALL_COMMAND $(MAKE) install_sw
            BUILD_IN_SOURCE 1
        )
        ExternalProject_Get_Property(openssl_static INSTALL_DIR)
        set(OSSL_INSTALL_DIR   "${INSTALL_DIR}")
        set(_openssl_prefix    "${OSSL_INSTALL_DIR}")
        set(_curl_openssl_flag --with-openssl=${_openssl_prefix})
        message(STATUS "Static curl build will use our OpenSSL at: ${_openssl_prefix}")

        # ── minizip from source (macOS static) ───────────────────────────────
        # Same story as OpenSSL: Homebrew's libminizip.a is built for the build
        # machine's macOS. The project uses the *classic* minizip API
        # (<minizip/zip.h>, zipOpen/unzOpen/…), which is just three C files in
        # zlib's contrib/minizip. Compile them ourselves for the exact arch +
        # deployment target against the system libz, and install headers under
        # include/minizip/ so the existing #include <minizip/zip.h> resolves.
        set(ZLIB_VERSION "1.3.1" CACHE STRING
            "zlib version whose contrib/minizip is built for the macOS static build")

        set(_mz_archflags "")
        foreach(_a ${CMAKE_OSX_ARCHITECTURES})
            list(APPEND _mz_archflags -arch ${_a})
        endforeach()
        set(_mz_minflag "")
        if(DEFINED CMAKE_OSX_DEPLOYMENT_TARGET AND CMAKE_OSX_DEPLOYMENT_TARGET)
            set(_mz_minflag -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET})
        endif()

        message(STATUS "Static build will compile minizip (zlib ${ZLIB_VERSION} contrib) from source")
        ExternalProject_Add(minizip_static
            URL https://github.com/madler/zlib/archive/refs/tags/v${ZLIB_VERSION}.tar.gz
            ${_ep_timestamp_opt}
            CONFIGURE_COMMAND ""
            BUILD_IN_SOURCE 1
            BUILD_COMMAND
                    cc ${_mz_archflags} ${_mz_minflag} -O2 -I<SOURCE_DIR> -I<SOURCE_DIR>/contrib/minizip -c contrib/minizip/ioapi.c -o ioapi.o
            COMMAND cc ${_mz_archflags} ${_mz_minflag} -O2 -I<SOURCE_DIR> -I<SOURCE_DIR>/contrib/minizip -c contrib/minizip/zip.c   -o zip.o
            COMMAND cc ${_mz_archflags} ${_mz_minflag} -O2 -I<SOURCE_DIR> -I<SOURCE_DIR>/contrib/minizip -c contrib/minizip/unzip.c -o unzip.o
            COMMAND ar rcs libminizip.a ioapi.o zip.o unzip.o
            INSTALL_COMMAND ${CMAKE_COMMAND} -E make_directory <INSTALL_DIR>/lib
            COMMAND ${CMAKE_COMMAND} -E make_directory <INSTALL_DIR>/include/minizip
            COMMAND ${CMAKE_COMMAND} -E copy <SOURCE_DIR>/libminizip.a          <INSTALL_DIR>/lib/libminizip.a
            COMMAND ${CMAKE_COMMAND} -E copy <SOURCE_DIR>/contrib/minizip/zip.h   <INSTALL_DIR>/include/minizip/zip.h
            COMMAND ${CMAKE_COMMAND} -E copy <SOURCE_DIR>/contrib/minizip/unzip.h <INSTALL_DIR>/include/minizip/unzip.h
            COMMAND ${CMAKE_COMMAND} -E copy <SOURCE_DIR>/contrib/minizip/ioapi.h <INSTALL_DIR>/include/minizip/ioapi.h
        )
        ExternalProject_Get_Property(minizip_static INSTALL_DIR)
        set(MZIP_INSTALL_DIR "${INSTALL_DIR}")
    else()
        # Linux: system OpenSSL -dev package (its libs already match the target).
        find_package(OpenSSL REQUIRED)
    endif()

    # curl's configure is a separate autotools build invoked via
    # ExternalProject_Add — it knows nothing about CMAKE_OSX_DEPLOYMENT_TARGET,
    # so without an explicit -mmacosx-version-min, its .o files default to
    # whatever SDK version the BUILD machine happens to have, which can be
    # newer than what CMAKE_OSX_DEPLOYMENT_TARGET asked for. That mismatch
    # produces "object file was built for newer macOS version" linker warnings
    # and can make the binary refuse to load on an older macOS test machine
    # even though the rest of the project correctly targeted the older OS.
    set(_curl_cflags "-fPIC")
    if(APPLE AND DEFINED CMAKE_OSX_DEPLOYMENT_TARGET AND CMAKE_OSX_DEPLOYMENT_TARGET)
        set(_curl_cflags "${_curl_cflags} -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
        message(STATUS "Static curl build will target macOS ${CMAKE_OSX_DEPLOYMENT_TARGET}+")
    endif()

    # Build a minimal curl (HTTPS only, no SSH/LDAP/RTMP/HTTP2/brotli/zstd)
    if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24")
        set(_curl_timestamp_opt DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    else()
        set(_curl_timestamp_opt "")
    endif()
    ExternalProject_Add(curl_static
        URL          https://curl.se/download/curl-8.7.1.tar.gz
        ${_curl_timestamp_opt}
        CONFIGURE_COMMAND
            <SOURCE_DIR>/configure
                --prefix=<INSTALL_DIR>
                --disable-shared
                --enable-static
                ${_curl_openssl_flag}
                --disable-ldap
                --disable-ldaps
                --disable-rtsp
                --disable-dict
                --disable-telnet
                --disable-tftp
                --disable-pop3
                --disable-imap
                --disable-smtp
                --disable-gopher
                --disable-smb
                --disable-mqtt
                --disable-rtmp
                --without-librtmp
                --without-brotli
                --without-zstd
                --without-libssh
                --without-libssh2
                --without-nghttp2
                --without-libidn2
                --without-libpsl
                --without-gssapi
                --without-krb4
                --disable-versioned-symbols
                "CFLAGS=${_curl_cflags}"
        BUILD_COMMAND   $(MAKE)
        INSTALL_COMMAND $(MAKE) install
        BUILD_IN_SOURCE 0
    )

    # On macOS curl must configure/link against the OpenSSL we just built, so
    # openssl_static has to finish (build + install) before curl starts.
    if(APPLE)
        add_dependencies(curl_static openssl_static)
    endif()

    ExternalProject_Get_Property(curl_static INSTALL_DIR)
    set(STATIC_CURL_INCLUDE "${INSTALL_DIR}/include")
    set(STATIC_CURL_LIB     "${INSTALL_DIR}/lib/libcurl.a")

    add_library(curl_static_lib STATIC IMPORTED GLOBAL)
    set_target_properties(curl_static_lib PROPERTIES
        IMPORTED_LOCATION "${STATIC_CURL_LIB}"
    )
    add_dependencies(curl_static_lib curl_static)

    if(NOT APPLE)
        add_link_options(-static-libgcc -static-libstdc++)
    endif()
endif()

# ── MinGW static: build a minimal Schannel curl from source (single-file exe) ──
# Windows' native TLS (Schannel) drops curl's whole optional-dependency tree
# (OpenSSL, brotli, zstd, idn2, psl, libssh2, nghttp2/3, ngtcp2), so the final
# binary needs none of those DLLs. HTTP_ONLY keeps just HTTP/HTTPS. This mirrors
# the MSVC Windows build, which also uses Schannel.
if(STATIC_BUILD AND MINGW)
    # project() only enabled CXX, so CMAKE_C_COMPILER is empty here — enable C so
    # the curl sub-build gets a valid compiler (curl is a C project).
    enable_language(C)
    include(ExternalProject)
    if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24")
        set(_curl_ts DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    else()
        set(_curl_ts "")
    endif()
    set(_CURL_INSTALL "${CMAKE_BINARY_DIR}/curl_install")
    ExternalProject_Add(curl_static_mingw
        URL https://curl.se/download/curl-8.7.1.tar.gz
        ${_curl_ts}
        CMAKE_ARGS
            -DCMAKE_BUILD_TYPE=Release
            -DCMAKE_INSTALL_PREFIX=${_CURL_INSTALL}
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
            -DCMAKE_RC_COMPILER=${CMAKE_RC_COMPILER}
            -DBUILD_SHARED_LIBS=OFF
            -DBUILD_CURL_EXE=OFF
            -DBUILD_TESTING=OFF
            -DHTTP_ONLY=ON
            -DCURL_USE_SCHANNEL=ON
            -DCURL_USE_OPENSSL=OFF
            -DCURL_USE_LIBSSH2=OFF
            -DCURL_USE_LIBPSL=OFF
            -DUSE_LIBIDN2=OFF
            -DCURL_BROTLI=OFF
            -DCURL_ZSTD=OFF
            -DUSE_NGHTTP2=OFF
            -DUSE_NGTCP2=OFF
            -DENABLE_UNIX_SOCKETS=OFF
        BUILD_BYPRODUCTS "${_CURL_INSTALL}/lib/libcurl.a"
    )
    set(STATIC_CURL_INCLUDE "${_CURL_INSTALL}/include")
    add_library(curl_static_lib STATIC IMPORTED GLOBAL)
    set_target_properties(curl_static_lib PROPERTIES
        IMPORTED_LOCATION "${_CURL_INSTALL}/lib/libcurl.a")
    add_dependencies(curl_static_lib curl_static_mingw)
    # Linking curl statically on Windows: consumers must define CURL_STATICLIB so
    # curl.h does not mark the API as __declspec(dllimport).
    add_compile_definitions(CURL_STATICLIB)
endif()

# ── Hint: if you didn't pass -DCMAKE_TOOLCHAIN_FILE, try to auto-detect vcpkg ─
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT} AND NOT MINGW)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "vcpkg toolchain")
    message(STATUS "Auto-detected vcpkg at $ENV{VCPKG_ROOT}")
endif()

# ── Dependencies via vcpkg (or system) ────────────────────────────────────────

# curl (skipped for MinGW static — we build our own minimal Schannel curl above)
if(NOT (STATIC_BUILD AND MINGW))
    find_package(CURL CONFIG QUIET)      # vcpkg installs a CONFIG-mode package
    if(NOT CURL_FOUND)
        find_package(CURL REQUIRED)      # system fallback (MODULE mode)
    endif()
endif()

# nlohmann/json
find_package(nlohmann_json CONFIG QUIET)
if(NOT nlohmann_json_FOUND)
    # Not installed — download single header at configure time
    set(JSON_DIR "${CMAKE_BINARY_DIR}/_json")
    set(JSON_HDR "${JSON_DIR}/nlohmann/json.hpp")
    if(NOT EXISTS "${JSON_HDR}")
        message(STATUS "Downloading nlohmann/json single header...")
        file(DOWNLOAD
            "https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp"
            "${JSON_HDR}"
            SHOW_PROGRESS
            STATUS DL_STATUS)
        list(GET DL_STATUS 0 DL_CODE)
        if(NOT DL_CODE EQUAL 0)
            message(FATAL_ERROR
                "Failed to download nlohmann/json. "
                "Install it via: vcpkg install nlohmann-json:x64-windows")
        endif()
    endif()
    add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
    target_include_directories(nlohmann_json::nlohmann_json INTERFACE "${JSON_DIR}")
endif()

# minizip (for cross-platform ZIP writing, used by IPA patching)
# Try CONFIG mode first (vcpkg), then pkg-config (Linux system), then manual find
find_package(minizip CONFIG QUIET)
if(NOT minizip_FOUND)
    find_package(unofficial-minizip CONFIG QUIET)
    if(unofficial-minizip_FOUND)
        add_library(minizip::minizip ALIAS unofficial::minizip::minizip)
        set(minizip_FOUND TRUE)
    endif()
endif()
if(NOT minizip_FOUND)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        # IMPORTED_TARGET makes pkg-config resolve full library paths into the
        # PkgConfig::MINIZIP target, so no -L search is needed. Plain
        # pkg_check_modules only yields the bare name (-lminizip) without a path,
        # which fails to link on Apple Silicon (Homebrew lives in
        # /opt/homebrew/lib, not searched by default): "ld: library 'minizip' not found".
        pkg_check_modules(MINIZIP QUIET IMPORTED_TARGET minizip)
        if(MINIZIP_FOUND)
            add_library(minizip::minizip INTERFACE IMPORTED)
            target_link_libraries(minizip::minizip INTERFACE PkgConfig::MINIZIP)
            set(minizip_FOUND TRUE)
        endif()
    endif()
endif()
if(NOT minizip_FOUND)
    # Manual fallback: look for zip.h / unzip.h directly
    find_path(MINIZIP_INCLUDE_DIR NAMES minizip/zip.h zip.h
              PATHS /usr/include /usr/local/include)
    find_library(MINIZIP_LIBRARY NAMES minizip
                 PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu)
    if(MINIZIP_INCLUDE_DIR AND MINIZIP_LIBRARY)
        add_library(minizip::minizip INTERFACE IMPORTED)
        target_include_directories(minizip::minizip INTERFACE ${MINIZIP_INCLUDE_DIR})
        target_link_libraries(minizip::minizip INTERFACE ${MINIZIP_LIBRARY})
        set(minizip_FOUND TRUE)
        message(STATUS "minizip found manually: ${MINIZIP_LIBRARY}")
    endif()
endif()

# MINIZIP_ENABLED is the honest "ZIP patching is available" flag for the summary.
# (minizip_FOUND gets cleared in the non-Windows static blocks so the dynamic
# minizip::minizip target isn't linked on top of the static .a — that clear is a
# link-gating detail, not a statement that minizip is unavailable.)
if(minizip_FOUND)
    message(STATUS "minizip found — full ZIP patching enabled")
    add_compile_definitions(HAVE_MINIZIP)
    set(MINIZIP_ENABLED TRUE)
elseif(STATIC_BUILD AND APPLE)
    # Built from source further below (with HAVE_MINIZIP forced on the target),
    # so the "not found" warning would be misleading here.
    message(STATUS "minizip will be built from source (macOS static)")
    set(MINIZIP_ENABLED TRUE)
else()
    set(MINIZIP_ENABLED FALSE)
    if(WIN32)
        message(WARNING
            "minizip NOT found — IPA zip patching will use fallback (metadata may be missing).\n"
            "Install with: vcpkg install minizip:x64-windows")
    else()
        message(WARNING
            "minizip NOT found — IPA zip patching will use fallback (metadata may be missing).\n"
            "Install with: sudo apt install libminizip-dev   (Debian/Ubuntu)\n"
            "              brew install minizip              (macOS)")
    endif()
endif()


find_package(ZLIB QUIET)

# ── OpenSSL (needed for --keychain-passphrase AES-256-GCM encryption) ─────────
if(STATIC_BUILD AND WIN32)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(OPENSSL_MSVC_STATIC_RT TRUE)
endif()
# macOS static builds OpenSSL from source (see top of file) and links its .a
# directly, so it needs neither a system/brew OpenSSL nor the CMake targets.
if(NOT (STATIC_BUILD AND APPLE))
    find_package(OpenSSL REQUIRED)
endif()

# MinGW static: link libcrypto.a directly (our AES/SHA only; curl uses Schannel,
# so libssl is not needed). find_package may hand back the .dll.a import lib, so
# resolve the static archive explicitly.
if(STATIC_BUILD AND MINGW)
    find_library(CRYPTO_STATIC_MINGW NAMES libcrypto.a crypto REQUIRED)
    message(STATUS "MinGW static libcrypto: ${CRYPTO_STATIC_MINGW}")
endif()


# Text formatting is provided by the dependency-free ipt::format() in
# compat_format.h — no std::format / {fmt} needed, so nothing to detect or link
# here. See that header for why (Apple availability-gating + <chrono> pulling in
# <format>).

# ── Unicorn Engine (for SAP signing: Apple dylib x86-64 emulation) ────────────
#
# Windows static:  vcpkg install unicorn:x64-windows-static
# Windows dynamic: vcpkg install unicorn:x64-windows
# Linux:           sudo apt install libunicorn-dev
# macOS:           brew install unicorn
#
# With the vcpkg toolchain active, find_library resolves the correct
# triplet's lib/ directory automatically — no explicit PATHS needed.

find_library(UNICORN_LIBRARY NAMES unicorn)
find_path(UNICORN_INCLUDE_DIR NAMES unicorn/unicorn.h)

# Fallback: scan common system paths if not found via vcpkg
if(NOT UNICORN_LIBRARY)
    find_library(UNICORN_LIBRARY NAMES unicorn
        PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
              /opt/homebrew/lib)
endif()
if(NOT UNICORN_INCLUDE_DIR)
    find_path(UNICORN_INCLUDE_DIR NAMES unicorn/unicorn.h
        PATHS /usr/include /usr/local/include /opt/homebrew/include)
endif()

# On macOS static build: always build unicorn from source to get .a
# A system .dylib from brew won't work for a fully static binary
if(STATIC_BUILD AND APPLE AND (NOT UNICORN_LIBRARY OR UNICORN_LIBRARY MATCHES "\.dylib$"))
    unset(UNICORN_LIBRARY CACHE)
    unset(UNICORN_INCLUDE_DIR CACHE)
    message(STATUS "macOS static build: will build unicorn.a from source")
endif()

# MinGW static: a found .dll.a would link dynamically — build the static .a from
# source instead (same GCC toolchain → fast TCG, no libunicorn.dll dependency).
if(STATIC_BUILD AND MINGW)
    unset(UNICORN_LIBRARY CACHE)
    unset(UNICORN_INCLUDE_DIR CACHE)
    message(STATUS "MinGW static build: will build libunicorn.a from source")
endif()

if(UNICORN_LIBRARY AND UNICORN_INCLUDE_DIR)
    message(STATUS "Unicorn Engine: ${UNICORN_LIBRARY}")
    message(STATUS "Unicorn headers: ${UNICORN_INCLUDE_DIR}")
elseif(APPLE)
    # On macOS: FetchContent breaks because Unicorn's nested project() loses
    # arch flags. Use ExternalProject_Add which runs cmake as a subprocess
    # with explicit CMAKE_ARGS — arch flags are properly forwarded.
    message(STATUS "System Unicorn not found — building static unicorn from source")
    include(ExternalProject)
    include(FetchContent)

    set(_UNICORN_INSTALL "${CMAKE_BINARY_DIR}/unicorn_install")

    ExternalProject_Add(unicorn_static_build
        GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
        GIT_TAG        2.1.4
        GIT_SHALLOW    TRUE
        ${_curl_timestamp_opt}
        CMAKE_ARGS
            -DCMAKE_BUILD_TYPE=Release
            -DCMAKE_INSTALL_PREFIX=${_UNICORN_INSTALL}
            -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
            -DCMAKE_OSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}
            -DUNICORN_BUILD_SHARED=OFF
            -DUNICORN_BUILD_SAMPLES=OFF
            -DUNICORN_BUILD_TESTS=OFF
            -DUNICORN_ARCH=x86
            -DUNICORN_ARCH_X86=ON
            -DUNICORN_ARCH_ARM=OFF
            -DUNICORN_ARCH_ARM64=OFF
            -DUNICORN_ARCH_MIPS=OFF
            -DUNICORN_ARCH_SPARC=OFF
            -DUNICORN_ARCH_PPC=OFF
            -DUNICORN_ARCH_RISCV=OFF
            -DUNICORN_ARCH_S390X=OFF
            -DUNICORN_ARCH_TRICORE=OFF
        BUILD_BYPRODUCTS "${_UNICORN_INSTALL}/lib/libunicorn.a"
    )

    set(UNICORN_LIBRARY    "${_UNICORN_INSTALL}/lib/libunicorn.a")
    set(UNICORN_INCLUDE_DIR "${_UNICORN_INSTALL}/include")
    set(UNICORN_NEEDS_EXTERNAL_BUILD TRUE)  # add_dependencies handled after add_executable

    # Patch at BUILD time (after unicorn install):
    # 1. Remove crc32c.c.o (which exports conflicting crc32 + needed crc32c)
    # 2. Add a stub that provides crc32c without crc32 (zlib covers crc32)
    set(_UNICORN_PATCH_SCRIPT "${CMAKE_BINARY_DIR}/patch_unicorn.sh")
    file(WRITE "${_UNICORN_PATCH_SCRIPT}" "#!/bin/sh
set -e
UNICORN_A=\"${_UNICORN_INSTALL}/lib/libunicorn.a\"
STUB_C=\"${CMAKE_BINARY_DIR}/crc32c_stub.c\"
STUB_O=\"${CMAKE_BINARY_DIR}/crc32c_stub.o\"

# crc32c stub: software implementation of CRC32C (Castagnoli polynomial)
# Provides the symbol that helper.c.o needs without conflicting with zlib
cat > \"\${STUB_C}\" << 'EOF'
#include <stdint.h>
#include <stddef.h>
uint32_t crc32c(uint32_t crc, const uint8_t *buf, size_t len) {
    crc = ~crc;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ ((uint32_t)0x82F63B78u & -((int)(crc & 1)));
    }
    return ~crc;
}
EOF

# Remove the conflicting object (exports duplicate crc32 + crc32c)
ar d \"\${UNICORN_A}\" crc32c.c.o || true

# Compile and add our crc32c stub
cc -O2 -arch ${CMAKE_OSX_ARCHITECTURES} -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET} -c \"\${STUB_C}\" -o \"\${STUB_O}\"
ar r \"\${UNICORN_A}\" \"\${STUB_O}\"
ranlib \"\${UNICORN_A}\"
echo \"unicorn patched: crc32c.c.o removed, crc32c stub added\"
")
    execute_process(COMMAND chmod +x "${_UNICORN_PATCH_SCRIPT}")

    ExternalProject_Add_Step(unicorn_static_build patch_crc32
        COMMAND sh "${_UNICORN_PATCH_SCRIPT}"
        DEPENDEES install
        COMMENT "Patching libunicorn.a: replacing crc32c.c.o with clean stub"
    )
    message(STATUS "Unicorn will be built as static lib: ${UNICORN_LIBRARY}")
elseif(NOT WIN32 OR MINGW)
    # Linux / MinGW-w64: build from source with the same GCC toolchain (fast TCG,
    # unlike an MSVC-built Unicorn). Static x86-only lib, ~30s.
    message(STATUS "System Unicorn not found — building from source (x86 only, ~30s)")
    include(FetchContent)
    FetchContent_Declare(
        unicorn_src
        GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
        GIT_TAG        2.1.4
        GIT_SHALLOW    TRUE
    )
    set(UNICORN_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(UNICORN_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)  # skip sample_x86, shellcode, …
    set(UNICORN_BUILD_TESTS   OFF CACHE BOOL "" FORCE)
    # unicorn 2.1.x selects targets via the UNICORN_ARCH *string* list, not the
    # per-arch UNICORN_ARCH_<NAME> booleans (those are ignored → all 16 QEMU
    # targets get built, which is huge and slow). We only emulate x86-64.
    set(UNICORN_ARCH "x86" CACHE STRING "" FORCE)
    FetchContent_MakeAvailable(unicorn_src)
    set(UNICORN_LIBRARY unicorn)
    set(UNICORN_INCLUDE_DIR ${unicorn_src_SOURCE_DIR}/include)
    message(STATUS "Unicorn built from source: ${UNICORN_INCLUDE_DIR}")
else()
    message(FATAL_ERROR
        "Unicorn Engine NOT found.\n"
        "  Windows: vcpkg install unicorn:x64-windows-static  (static build)\n"
        "           vcpkg install unicorn:x64-windows          (dynamic build)\n"
        "  Or pass: -DUNICORN_LIBRARY=<path/to/unicorn.lib> -DUNICORN_INCLUDE_DIR=<path>\n"
    )
endif()



# ── Target ────────────────────────────────────────────────────────────────────

add_executable(ipatool
    main.cpp
    protect.cpp
    hwid.cpp
    device_mac.cpp
    appstore.cpp
    http_client.cpp
    plist.cpp
    sha2.cpp
    aes.cpp
    # SAP signing (v2.4.0+): Unicorn-based Apple dylib emulator
    MachImage.cpp
    SapMachine.cpp
    SapSigner.cpp
    StoreAgentMachine.cpp
    purchase_flow.cpp
    # Windows resources (SAP assets embedded in EXE)
    $<$<PLATFORM_ID:Windows>:sap_resources.rc>
    # Headers
    appstore.h
    device_mac.h
    ipatool.h
    protect.h
    http_client.h
    hwid.h
    plist.h
    sha2.h
    aes.h
    MachImage.h
    SapMachine.h
    SapSigner.h
    StoreAgentMachine.h
)

target_include_directories(ipatool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${UNICORN_INCLUDE_DIR}
)

if(UNICORN_NEEDS_EXTERNAL_BUILD)
    add_dependencies(ipatool unicorn_static_build)
endif()

# ── SAP asset embedding ───────────────────────────────────────────────────────
# Linux:   objcopy --input binary → ELF .o with _binary_<name>_start symbols
# macOS:   CMake-generated .S assembly with .incbin → Mach-O .o (same symbols)
# Windows: .rc RCDATA (already handled above)
# Fallback (any platform): load from sap_assets/ directory at runtime

set(_SAP_ASSETS CoreFP CommerceCore CommerceKit "CoreFP.icxs" storeagent)

if(NOT WIN32)
    if(APPLE)
        # ── macOS: generate .S files with .incbin ────────────────────────────
        # Apple ld64 requires Mach-O objects — objcopy ELF output won't link.
        # Clang/Apple assembler supports .incbin natively.
        # Mach-O symbol convention: C `_binary_X_start` → asm `__binary_X_start`
        # (compiler adds one underscore, so we write two in asm).
        enable_language(ASM)   # needed to compile .S assembly files
        set(_SAP_OBJS "")
        foreach(_ASSET ${_SAP_ASSETS})
            string(REGEX REPLACE "[^A-Za-z0-9_]" "_" _SYM ${_ASSET})
            set(_ASM "${CMAKE_BINARY_DIR}/sap_asset_${_SYM}.S")
            set(_SRC "${CMAKE_CURRENT_SOURCE_DIR}/sap_assets/${_ASSET}")

            # Write the assembly file at configure time using configure_file trick
            # to handle the path properly (avoids CMake quoting issues with .incbin)
            set(_ASM_CONTENT ".section __DATA,__sap_assets
.global __binary_${_SYM}_start
__binary_${_SYM}_start:
    .incbin \"${_SRC}\"
__binary_${_SYM}_end:
.global __binary_${_SYM}_end
")
            file(WRITE "${_ASM}" "${_ASM_CONTENT}")
            list(APPEND _SAP_OBJS ${_ASM})
        endforeach()

        target_sources(ipatool PRIVATE ${_SAP_OBJS})
        target_compile_definitions(ipatool PRIVATE SAP_ASSETS_EMBEDDED=1)
        message(STATUS "SAP assets: embedding via .incbin assembly (macOS)")

    else()
        # ── Linux: objcopy --input binary ────────────────────────────────────
        find_program(OBJCOPY_CMD NAMES objcopy
                     DOC "objcopy for embedding SAP binary assets")

        if(OBJCOPY_CMD)
            if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
                set(_OC_FMT  "elf64-x86-64")
                set(_OC_ARCH "i386:x86-64")
            elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
                set(_OC_FMT  "elf64-aarch64")
                set(_OC_ARCH "aarch64")
            else()
                set(_OC_FMT  "elf64-x86-64")
                set(_OC_ARCH "i386:x86-64")
            endif()

            set(_SAP_OBJS "")
            foreach(_ASSET ${_SAP_ASSETS})
                string(REGEX REPLACE "[^A-Za-z0-9_]" "_" _SYM ${_ASSET})
                set(_OBJ "${CMAKE_BINARY_DIR}/sap_asset_${_SYM}.o")
                set(_SRC "${CMAKE_CURRENT_SOURCE_DIR}/sap_assets/${_ASSET}")

                add_custom_command(
                    OUTPUT  ${_OBJ}
                    COMMAND ${OBJCOPY_CMD}
                            --input-target  binary
                            --output-target ${_OC_FMT}
                            --binary-architecture ${_OC_ARCH}
                            ${_ASSET}
                            ${_OBJ}
                    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/sap_assets"
                    DEPENDS ${_SRC}
                    COMMENT "Embedding SAP asset: ${_ASSET}"
                    VERBATIM
                )
                list(APPEND _SAP_OBJS ${_OBJ})
            endforeach()

            target_sources(ipatool PRIVATE ${_SAP_OBJS})
            target_compile_definitions(ipatool PRIVATE SAP_ASSETS_EMBEDDED=1)
            message(STATUS "SAP assets: embedding via objcopy (Linux)")
        else()
            message(STATUS "SAP assets: objcopy not found — will load from sap_assets/ at runtime")
        endif()
    endif()
endif()

if(STATIC_BUILD AND NOT WIN32 AND NOT APPLE)
    # Force static versions of OpenSSL, zlib, minizip by using full paths
    find_library(OPENSSL_SSL_STATIC    NAMES libssl.a    PATHS /usr/lib/x86_64-linux-gnu REQUIRED NO_DEFAULT_PATH)
    find_library(OPENSSL_CRYPTO_STATIC NAMES libcrypto.a PATHS /usr/lib/x86_64-linux-gnu REQUIRED NO_DEFAULT_PATH)
    find_library(ZLIB_STATIC           NAMES libz.a      PATHS /usr/lib/x86_64-linux-gnu REQUIRED NO_DEFAULT_PATH)
    find_library(MINIZIP_STATIC        NAMES libminizip.a
                 PATHS /usr/lib/x86_64-linux-gnu /usr/lib/gcc/x86_64-linux-gnu/11
                       /usr/lib/gcc/x86_64-linux-gnu/12 /usr/lib/gcc/x86_64-linux-gnu/13)

    message(STATUS "Static OpenSSL SSL:    ${OPENSSL_SSL_STATIC}")
    message(STATUS "Static OpenSSL Crypto: ${OPENSSL_CRYPTO_STATIC}")
    message(STATUS "Static zlib:           ${ZLIB_STATIC}")
    message(STATUS "Static minizip:        ${MINIZIP_STATIC}")

    set(STATIC_LINK_LIBS
        curl_static_lib
        nlohmann_json::nlohmann_json
        ${OPENSSL_SSL_STATIC}
        ${OPENSSL_CRYPTO_STATIC}
        ${UNICORN_LIBRARY}
        dl pthread
    )
    if(MINIZIP_STATIC)
        list(APPEND STATIC_LINK_LIBS ${MINIZIP_STATIC})
        set(minizip_FOUND FALSE)  # don't also link the dynamic minizip::minizip target below
    endif()
    list(APPEND STATIC_LINK_LIBS ${ZLIB_STATIC})
endif()

if(STATIC_BUILD AND APPLE AND NOT UNICORN_NEEDS_EXTERNAL_BUILD)
    # ── crc32 conflict fix (macOS, system/brew .a only) ──────────────────────
    # When unicorn comes from ExternalProject, patching is done at BUILD time
    # via ExternalProject_Add_Step — skip this configure-time block.
    if(UNICORN_LIBRARY MATCHES "\.a$")
        find_program(AR_CMD ar REQUIRED)
        set(_UNICORN_PATCHED "${CMAKE_BINARY_DIR}/libunicorn_nocrc32.a")
        file(REMOVE "${_UNICORN_PATCHED}")
        message(STATUS "Patching system unicorn: removing bundled crc32c.c.o...")
        execute_process(COMMAND cp -f "${UNICORN_LIBRARY}" "${_UNICORN_PATCHED}"
                        RESULT_VARIABLE _CP_RES)
        if(_CP_RES EQUAL 0)
            execute_process(COMMAND chmod u+w "${_UNICORN_PATCHED}")
            execute_process(COMMAND ${AR_CMD} d "${_UNICORN_PATCHED}" crc32c.c.o
                            RESULT_VARIABLE _AR_RES)
            if(_AR_RES EQUAL 0)
                message(STATUS "libunicorn_nocrc32.a created OK")
                set(UNICORN_LIBRARY "${_UNICORN_PATCHED}")
            else()
                message(WARNING "ar d failed — using original .a")
            endif()
        else()
            message(WARNING "cp failed — using original .a")
        endif()
    endif() # if(UNICORN_LIBRARY MATCHES .a)
endif() # if(STATIC_BUILD AND APPLE AND NOT UNICORN_NEEDS_EXTERNAL_BUILD)

if(STATIC_BUILD AND APPLE)
    # OpenSSL was built from source at the top of this file. Its static libs are
    # produced at BUILD time, so we can't find_library() them now (they don't
    # exist yet at configure time) — reference the install paths directly and
    # make ipatool depend on openssl_static so it's compiled/installed first.
    # Its headers also come from there (no brew openssl on the include path).
    # zlib is left dynamic — it's a system library on every Mac (/usr/lib/libz.1.dylib),
    # not a Homebrew dependency, so there's no portability reason to statically link it,
    # and Homebrew doesn't ship a zlib formula by default (it'd require a separate install).
    set(OPENSSL_SSL_STATIC    "${OSSL_INSTALL_DIR}/lib/libssl.a")
    set(OPENSSL_CRYPTO_STATIC "${OSSL_INSTALL_DIR}/lib/libcrypto.a")
    add_dependencies(ipatool openssl_static)
    target_include_directories(ipatool PRIVATE "${OSSL_INSTALL_DIR}/include")

    # minizip was also built from source (see top of file); reference its install
    # paths directly and depend on the target. HAVE_MINIZIP is normally set at
    # configure time from a found system/brew minizip — force it on here since we
    # supply our own and no brew minizip need be installed. (add_compile_definitions
    # wouldn't reach the already-created ipatool target, so use the target form.)
    set(MINIZIP_STATIC "${MZIP_INSTALL_DIR}/lib/libminizip.a")
    add_dependencies(ipatool minizip_static)
    target_include_directories(ipatool PRIVATE "${MZIP_INSTALL_DIR}/include")
    target_compile_definitions(ipatool PRIVATE HAVE_MINIZIP)

    message(STATUS "Static OpenSSL SSL:    ${OPENSSL_SSL_STATIC}")
    message(STATUS "Static OpenSSL Crypto: ${OPENSSL_CRYPTO_STATIC}")
    message(STATUS "Static minizip:        ${MINIZIP_STATIC}")

    set(STATIC_LINK_LIBS
        curl_static_lib
        nlohmann_json::nlohmann_json
        ${OPENSSL_SSL_STATIC}
        ${OPENSSL_CRYPTO_STATIC}
        z
        "-framework IOKit"
        "-framework CoreFoundation"
        "-framework SystemConfiguration"
        "-framework CoreServices"
    )
    if(MINIZIP_STATIC)
        list(APPEND STATIC_LINK_LIBS ${MINIZIP_STATIC})
        set(minizip_FOUND FALSE)  # don't also link the dynamic minizip::minizip target below
    endif()
endif()

if(STATIC_BUILD AND MINGW)
    # ── MinGW single-file static ────────────────────────────────────────────────
    # Our minimal Schannel curl + static libcrypto/unicorn/minizip; no third-party
    # DLLs. minizip.a needs zlib+bzip2 → --start-group resolves archive ordering.
    target_link_libraries(ipatool PRIVATE
        curl_static_lib
        nlohmann_json::nlohmann_json
        ${UNICORN_LIBRARY}
        ${CRYPTO_STATIC_MINGW}
        -Wl,--start-group -lminizip -lz -lbz2 -Wl,--end-group
        # Schannel + Windows system deps
        ws2_32 crypt32 bcrypt secur32 wldap32 normaliz winhttp iphlpapi shell32)
    target_include_directories(ipatool PRIVATE "${STATIC_CURL_INCLUDE}")
    add_dependencies(ipatool curl_static_mingw)
    # -static → pull libgcc/libstdc++/libwinpthread in too; unicorn bundles its
    # own zlib (crc32c.c) → allow the duplicate.
    target_link_options(ipatool PRIVATE
        -static -static-libgcc -static-libstdc++ -Wl,--allow-multiple-definition)
elseif(STATIC_BUILD AND NOT WIN32 AND NOT APPLE)
    # Linux static: use full .a paths built above
    target_link_libraries(ipatool PRIVATE ${STATIC_LINK_LIBS})
    add_dependencies(ipatool curl_static)
    target_include_directories(ipatool PRIVATE "${STATIC_CURL_INCLUDE}")
    # unicorn bundles its own zlib (crc32c.c) — same conflict as on Windows
    # --allow-multiple-definition = Linux equivalent of /FORCE:MULTIPLE
    target_link_options(ipatool PRIVATE -Wl,--allow-multiple-definition)
elseif(STATIC_BUILD AND APPLE)
    # ── crc32 conflict fix (macOS) ───────────────────────────────────────────
    # unicorn bundles its own zlib (crc32c.c.o). macOS ld64 has no
    # --allow-multiple-definition. Fix: strip the duplicate from a copy of
    # the unicorn archive using 'ar d' at configure time.
    if(UNICORN_NEEDS_EXTERNAL_BUILD)
        # ExternalProject: unicorn .a is patched at BUILD time via Add_Step
        # Just link the final path — it will exist by link time
        list(APPEND STATIC_LINK_LIBS "${UNICORN_LIBRARY}")
        message(STATUS "Unicorn: will link ExternalProject static lib (patched at build time)")
    elseif(UNICORN_LIBRARY MATCHES "\.a$")
        # System/brew .a: patch at configure time
        message(STATUS "Unicorn is static .a — patching crc32 at configure time...")
        find_program(AR_CMD ar REQUIRED)
        set(_UNICORN_PATCHED "${CMAKE_BINARY_DIR}/libunicorn_nocrc32.a")
        file(REMOVE "${_UNICORN_PATCHED}")
        execute_process(COMMAND cp -f "${UNICORN_LIBRARY}" "${_UNICORN_PATCHED}")
        execute_process(COMMAND chmod u+w "${_UNICORN_PATCHED}")
        execute_process(COMMAND ${AR_CMD} d "${_UNICORN_PATCHED}" crc32c.c.o
                        RESULT_VARIABLE _AR_RES)
        if(_AR_RES EQUAL 0)
            message(STATUS "libunicorn_nocrc32.a OK")
            list(APPEND STATIC_LINK_LIBS "${_UNICORN_PATCHED}")
        else()
            message(WARNING "ar d failed — linking original .a")
            list(APPEND STATIC_LINK_LIBS "${UNICORN_LIBRARY}")
        endif()
    else()
        # .dylib — no crc32 conflict
        message(STATUS "Unicorn is .dylib — no crc32 patch needed")
        list(APPEND STATIC_LINK_LIBS "${UNICORN_LIBRARY}")
    endif()
    # macOS static: same idea as Linux — full .a paths, our own minimal curl
    message(STATUS "STATIC_LINK_LIBS: ${STATIC_LINK_LIBS}")
    target_link_libraries(ipatool PRIVATE ${STATIC_LINK_LIBS})
    add_dependencies(ipatool curl_static)
    target_include_directories(ipatool PRIVATE "${STATIC_CURL_INCLUDE}")
else()
    target_link_libraries(ipatool
        PRIVATE
            CURL::libcurl
            nlohmann_json::nlohmann_json
            ${UNICORN_LIBRARY}
    )
    if(NOT (STATIC_BUILD AND WIN32))
        # Dynamic build or non-Windows: use CMake OpenSSL targets normally
        target_link_libraries(ipatool PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
endif()
if(minizip_FOUND AND NOT MINGW)
    # MinGW links minizip (+z +bz2) itself in a --start-group above.
    target_link_libraries(ipatool PRIVATE minizip::minizip)
endif()

# ── Platform-specific ─────────────────────────────────────────────────────────

if(WIN32)
  if(MSVC)
    # iphlpapi  = GetAdaptersInfo (MAC address)
    # ws2_32    = Winsock (used by curl internally too)
    target_link_libraries(ipatool PRIVATE iphlpapi ws2_32 winhttp crypt32 wldap32 normaliz shell32)

    # ── Release build: strip debug info from EXE, keep PDB separate ─────────────
    # /DEBUG:NONE  — no debug directory embedded in EXE (no PDB reference)
    # /OPT:REF     — remove unreferenced functions/data (smaller binary)
    # /OPT:ICF     — identical COMDAT folding (smaller binary)
    target_compile_options(ipatool PRIVATE
        $<$<CONFIG:Release>:/O2 /Ob2 /GL /DNDEBUG>
        $<$<CONFIG:RelWithDebInfo>:/O2 /Zi>
    )
    target_link_options(ipatool PRIVATE
        $<$<CONFIG:Release>:/DEBUG:NONE /OPT:REF /OPT:ICF /LTCG>
    )

    # ── Linker fixes for static build ─────────────────────────────────────────
    # /FORCE:MULTIPLE  — unicorn.lib bundles its own zlib (crc32c.c), which
    #                    conflicts with the project's zlib.lib. Both crc32
    #                    implementations are equivalent; pick one and continue.
    # /NODEFAULTLIB:LIBCMTD — exclude debug CRT that unicorn.lib may pull in
    #                         when linking a Release static build.
    # ── unicorn.lib bundles its own zlib (crc32c.c.obj) — conflicts with zlib.lib ──
    # /FORCE:MULTIPLE picks one definition and continues; LNK4088 appears but
    # the exe IS functional — it's a known false alarm for duplicate-symbol /FORCE.
    # See: https://learn.microsoft.com/en-us/cpp/build/reference/force-force-file-output
    target_link_libraries(ipatool PRIVATE "${UNICORN_LIBRARY}")
    target_link_options(ipatool PRIVATE
        /FORCE:MULTIPLE
        /IGNORE:4006           # suppress the "already defined" noise
        /NODEFAULTLIB:LIBCMTD  # exclude debug CRT from Release build
    )

    # Suppress MSVC warnings about "unsafe" CRT functions
    target_compile_definitions(ipatool PRIVATE
        _CRT_SECURE_NO_WARNINGS
        _WINSOCK_DEPRECATED_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )

    # MSVC warning flags
    target_compile_options(ipatool PRIVATE /W3 /wd4996)

    if(STATIC_BUILD)
        message(STATUS "Windows static build: using x64-windows-static triplet")
        # Derive vcpkg root from the toolchain file path:
        #   <vcpkg_root>/scripts/buildsystems/vcpkg.cmake  →  go up 3 levels
        get_filename_component(_TC "${CMAKE_TOOLCHAIN_FILE}" REALPATH)
        get_filename_component(_TC "${_TC}" DIRECTORY)   # buildsystems
        get_filename_component(_TC "${_TC}" DIRECTORY)   # scripts
        get_filename_component(_VCPKG_ROOT "${_TC}" DIRECTORY)  # vcpkg root
        set(_SSL_STATIC_DIR "${_VCPKG_ROOT}/installed/x64-windows-static")
        message(STATUS "Static OpenSSL dir: ${_SSL_STATIC_DIR}")
        if(NOT EXISTS "${_SSL_STATIC_DIR}/lib/libssl.lib")
            message(FATAL_ERROR
                "libssl.lib not found at ${_SSL_STATIC_DIR}/lib/\n"
                "Run: vcpkg install openssl:x64-windows-static")
        endif()
        target_include_directories(ipatool PRIVATE "${_SSL_STATIC_DIR}/include")
        target_link_libraries(ipatool PRIVATE
            "${_SSL_STATIC_DIR}/lib/libssl.lib"
            "${_SSL_STATIC_DIR}/lib/libcrypto.lib"
        )
    endif()
  else()
    # ── MinGW-w64 (GCC) ─────────────────────────────────────────────────────────
    target_compile_options(ipatool PRIVATE -O2 -Wall -Wextra -Wno-unused-parameter)
    target_compile_definitions(ipatool PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_link_options(ipatool PRIVATE -Wl,--allow-multiple-definition)
    if(NOT STATIC_BUILD)
        # Dynamic MinGW: the generic block already linked curl/openssl/unicorn;
        # add the Windows system deps + minizip here. (Static is fully handled by
        # the MinGW single-file branch above.)
        # winhttp: SapWinHttpClient (the MSVC #pragma comment is ignored by GCC).
        target_link_libraries(ipatool PRIVATE
            iphlpapi ws2_32 crypt32 bcrypt secur32 wldap32 normaliz winhttp shell32
            -Wl,--start-group -lminizip -lz -lbz2 -Wl,--end-group)
        target_link_options(ipatool PRIVATE -static-libgcc -static-libstdc++)
    endif()
  endif()
else()
    target_compile_options(ipatool PRIVATE -Wall -Wextra -Wno-unused-parameter)
    if(APPLE AND NOT STATIC_BUILD)
        # IOKit needed for hwid.h (IOPlatformSerialNumber, IOPlatformUUID)
        # The rest are transitive dependencies of a dynamically-linked libcurl:
        #   SystemConfiguration — SCDynamicStoreCopyProxies (system proxy detection)
        #   CoreServices        — pulled in alongside SystemConfiguration on macOS
        #   z                   — zlib, used by curl's gzip/deflate Content-Encoding support
        # All of these are system libraries/frameworks present on every Mac —
        # not Homebrew dependencies, so static-linking them isn't possible or
        # necessary; linking against them dynamically doesn't affect portability.
        # (When STATIC_BUILD is on, all five are already added via
        # STATIC_LINK_LIBS above, IOKit included — adding them again here
        # would just produce harmless "duplicate libraries" linker warnings.)
        target_link_libraries(ipatool PRIVATE
            "-framework IOKit"
            "-framework CoreFoundation"
            "-framework SystemConfiguration"
            "-framework CoreServices"
            z
        )
    endif()
endif()

# ── Install ───────────────────────────────────────────────────────────────────

install(TARGETS ipatool DESTINATION bin)

if(BUILD_TESTING)
    add_executable(purchase_flow_tests
        tests/purchase_flow_tests.cpp
        purchase_flow.cpp
        plist.cpp
    )
    target_include_directories(purchase_flow_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME purchase_flow_tests COMMAND purchase_flow_tests)
endif()

# ── Helper message ────────────────────────────────────────────────────────────

message(STATUS "")
message(STATUS "=== ipatool build configuration ===")
message(STATUS "  Platform  : ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Compiler  : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  CURL      : found")
message(STATUS "  minizip   : ${MINIZIP_ENABLED}")
message(STATUS "  unicorn   : ${UNICORN_LIBRARY}")
message(STATUS "  static    : ${STATIC_BUILD}")
message(STATUS "")
if(MINGW)
    message(STATUS "  Quick-start (Windows / MSYS2 MinGW-w64, single-file static):")
    message(STATUS "    pacman -S mingw-w64-x86_64-{gcc,cmake,ninja,openssl,minizip,zlib,bzip2,nlohmann-json} perl")
    message(STATUS "    cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DSTATIC_BUILD=ON")
    message(STATUS "    cmake --build build")
    message(STATUS "    (curl [Schannel] and unicorn [x86] are built from source → no third-party DLLs)")
elseif(WIN32)
    if(STATIC_BUILD)
        message(STATUS "  Quick-start (Windows static):")
        message(STATUS "    vcpkg install curl nlohmann-json minizip openssl unicorn --triplet x64-windows-static")
        message(STATUS "    cmake -B build -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake -DSTATIC_BUILD=ON -DVCPKG_TARGET_TRIPLET=x64-windows-static")
        message(STATUS "    cmake --build build --config Release")
    else()
        message(STATUS "  Quick-start with vcpkg:")
        message(STATUS "    vcpkg install curl nlohmann-json minizip openssl unicorn --triplet x64-windows")
        message(STATUS "    cmake -B build -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake")
        message(STATUS "    cmake --build build --config Release")
    endif()
elseif(APPLE)
    if(STATIC_BUILD)
        message(STATUS "  Quick-start (macOS, fully static single-file binary):")
        message(STATUS "    brew install nlohmann-json unicorn pkg-config")
        message(STATUS "    cmake -B build -DCMAKE_BUILD_TYPE=Release -DSTATIC_BUILD=ON \\")
        message(STATUS "          -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0")
        message(STATUS "    cmake --build build")
        message(STATUS "    (curl, OpenSSL, minizip and unicorn are built from source → no brew runtime deps)")
    else()
        message(STATUS "  Quick-start (macOS):")
        message(STATUS "    brew install curl nlohmann-json minizip openssl@3 unicorn")
        message(STATUS "    cmake -B build -DCMAKE_BUILD_TYPE=Release \\")
        message(STATUS "          -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3) && cmake --build build")
    endif()
else()
    message(STATUS "  Quick-start (Linux):")
    message(STATUS "    sudo apt install libcurl4-openssl-dev nlohmann-json3-dev libminizip-dev")
    message(STATUS "    cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build")
endif()
message(STATUS "")
