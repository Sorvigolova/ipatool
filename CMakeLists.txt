cmake_minimum_required(VERSION 3.20)

# ── Static linking option (must be before project() for MSVC CRT selection) ───
option(STATIC_BUILD "Build a static binary (Linux and Windows)" OFF)

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

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(STATIC_BUILD AND NOT WIN32 AND NOT APPLE)
    message(STATUS "Static build enabled — will build curl from source")
    set(BUILD_SHARED_LIBS OFF)

    include(ExternalProject)
    find_package(OpenSSL REQUIRED)

    # Build a minimal curl (HTTPS only, no SSH/LDAP/RTMP/HTTP2/brotli/zstd)
    ExternalProject_Add(curl_static
        URL          https://curl.se/download/curl-8.7.1.tar.gz
        CONFIGURE_COMMAND
            <SOURCE_DIR>/configure
                --prefix=<INSTALL_DIR>
                --disable-shared
                --enable-static
                --with-openssl
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
                "CFLAGS=-fPIC"
        BUILD_COMMAND   $(MAKE)
        INSTALL_COMMAND $(MAKE) install
        BUILD_IN_SOURCE 0
    )

    ExternalProject_Get_Property(curl_static INSTALL_DIR)
    set(STATIC_CURL_INCLUDE "${INSTALL_DIR}/include")
    set(STATIC_CURL_LIB     "${INSTALL_DIR}/lib/libcurl.a")

    add_library(curl_static_lib STATIC IMPORTED GLOBAL)
    set_target_properties(curl_static_lib PROPERTIES
        IMPORTED_LOCATION "${STATIC_CURL_LIB}"
    )
    add_dependencies(curl_static_lib curl_static)

    add_link_options(-static-libgcc -static-libstdc++)
endif()

# ── Hint: if you didn't pass -DCMAKE_TOOLCHAIN_FILE, try to auto-detect vcpkg ─
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "vcpkg toolchain")
    message(STATUS "Auto-detected vcpkg at $ENV{VCPKG_ROOT}")
endif()

# ── Dependencies via vcpkg (or system) ────────────────────────────────────────

# curl
find_package(CURL CONFIG QUIET)          # vcpkg installs a CONFIG-mode package
if(NOT CURL_FOUND)
    find_package(CURL REQUIRED)          # system fallback (MODULE mode)
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
        pkg_check_modules(MINIZIP QUIET minizip)
        if(MINIZIP_FOUND)
            add_library(minizip::minizip INTERFACE IMPORTED)
            target_include_directories(minizip::minizip INTERFACE ${MINIZIP_INCLUDE_DIRS})
            target_link_libraries(minizip::minizip INTERFACE ${MINIZIP_LIBRARIES})
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

if(minizip_FOUND)
    message(STATUS "minizip found — full ZIP patching enabled")
    add_compile_definitions(HAVE_MINIZIP)
else()
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
find_package(OpenSSL REQUIRED)

# ── Target ────────────────────────────────────────────────────────────────────

add_executable(ipatool main.cpp)

target_include_directories(ipatool PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

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
        dl pthread
    )
    if(MINIZIP_STATIC)
        list(APPEND STATIC_LINK_LIBS ${MINIZIP_STATIC})
    endif()
    list(APPEND STATIC_LINK_LIBS ${ZLIB_STATIC})
endif()

if(STATIC_BUILD AND NOT WIN32 AND NOT APPLE)
    # Linux static: use full .a paths built above
    target_link_libraries(ipatool PRIVATE ${STATIC_LINK_LIBS})
    add_dependencies(ipatool curl_static)
    target_include_directories(ipatool PRIVATE "${STATIC_CURL_INCLUDE}")
else()
    target_link_libraries(ipatool
        PRIVATE
            CURL::libcurl
            nlohmann_json::nlohmann_json
    )
    if(NOT (STATIC_BUILD AND WIN32))
        # Dynamic build or non-Windows: use CMake OpenSSL targets normally
        target_link_libraries(ipatool PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
endif()
if(minizip_FOUND)
    target_link_libraries(ipatool PRIVATE minizip::minizip)
endif()

# ── Platform-specific ─────────────────────────────────────────────────────────

if(WIN32)
    # iphlpapi  = GetAdaptersInfo (MAC address)
    # ws2_32    = Winsock (used by curl internally too)
    target_link_libraries(ipatool PRIVATE iphlpapi ws2_32 crypt32 wldap32 normaliz)

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
    target_compile_options(ipatool PRIVATE -Wall -Wextra -Wno-unused-parameter)
    if(APPLE)
        # IOKit needed for hwid.h (IOPlatformSerialNumber, IOPlatformUUID)
        target_link_libraries(ipatool PRIVATE
            "-framework IOKit"
            "-framework CoreFoundation"
        )
    endif()
endif()

# ── Install ───────────────────────────────────────────────────────────────────

install(TARGETS ipatool DESTINATION bin)

# ── Helper message ────────────────────────────────────────────────────────────

message(STATUS "")
message(STATUS "=== ipatool build configuration ===")
message(STATUS "  Platform  : ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Compiler  : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  CURL      : found")
message(STATUS "  minizip   : ${minizip_FOUND}")
message(STATUS "  static    : ${STATIC_BUILD}")
message(STATUS "")
if(WIN32)
    if(STATIC_BUILD)
        message(STATUS "  Quick-start (Windows static):")
        message(STATUS "    vcpkg install curl nlohmann-json minizip openssl --triplet x64-windows-static")
        message(STATUS "    cmake -B build -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake -DSTATIC_BUILD=ON -DVCPKG_TARGET_TRIPLET=x64-windows-static")
        message(STATUS "    cmake --build build --config Release")
    else()
        message(STATUS "  Quick-start with vcpkg:")
        message(STATUS "    vcpkg install curl nlohmann-json minizip openssl --triplet x64-windows")
        message(STATUS "    cmake -B build -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake")
        message(STATUS "    cmake --build build --config Release")
    endif()
elseif(APPLE)
    message(STATUS "  Quick-start (macOS):")
    message(STATUS "    brew install curl nlohmann-json minizip")
    message(STATUS "    cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build")
else()
    message(STATUS "  Quick-start (Linux):")
    message(STATUS "    sudo apt install libcurl4-openssl-dev nlohmann-json3-dev libminizip-dev")
    message(STATUS "    cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build")
endif()
message(STATUS "")
