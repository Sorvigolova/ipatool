# ipatool-cpp

A C++20 port of [ipatool](https://github.com/majd/ipatool) — a command-line tool for downloading iOS (and macOS) app packages from the App Store.
Uses **libcurl** for networking and a small **Unicorn Engine** sandbox to run Apple's FairPlay code for request signing and package decryption. Builds on **Windows (VS 2022)**, Linux, and macOS, with optional fully static binaries.

> C++20 is required. Text formatting uses a small dependency-free `ipt::format()` (see `compat_format.h`), so there is **no `std::format` / fmtlib dependency** and no toolchain-version caveats around `<format>`.

---

## What it does

- Authenticates with the App Store and downloads apps you own as `.ipa` (iOS) or decrypted `.pkg` (macOS).
- Signs every authentication request with an Apple **SAP action signature** (`X-Apple-ActionSignature`), required by the modern App Store protocol.
- Generates a **kbsync** blob locally and uses it for the `ent/download` download stage, falling back to the classic `volumeStore → redownload → updateProduct` chain.
- Decrypts encrypted macOS `.pkg` downloads.

SAP signing, kbsync generation and `.pkg` decryption are done by emulating Apple's own obfuscated dylibs (`CoreFP`, `CommerceCore`, `CommerceKit`, `storeagent`) inside a Unicorn x86-64 sandbox — no Apple binaries run natively on the host. Those asset files live in `sap_assets/` and are embedded into the executable at build time.

---

## Security model

ipatool-cpp protects your Apple ID credentials using machine-bound encryption — the account file is tied to the machine it was created on and cannot be decrypted elsewhere.

**Account file encryption:**
- Credentials are always encrypted with AES-256-GCM — plaintext storage is not supported
- File format version `0x02` — older formats are rejected with a clear re-login message
- Encryption key: `PBKDF2-SHA256(machine_id + "nice_key_is_nice" + passphrase, random_salt, 100000, 32)`
- `passphrase` is `""` if `--keychain-passphrase` is not provided — machine binding alone is sufficient
- Copying the account file to another machine produces an unreadable file

**Machine ID derivation (per platform):**
- **Windows**: `SHA256(ProductId + MachineGuid)` — from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` and `HKLM\SOFTWARE\Microsoft\Cryptography`
- **Linux**: `SHA256(machine-id + product_uuid)` — from `/etc/machine-id` and `/sys/class/dmi/id/product_uuid`
- **macOS**: `SHA256(IOPlatformSerialNumber + IOPlatformUUID)` — via IOKit

**In-memory protection:**
- Sensitive fields (`passwordToken`, `password`) are AES-256-GCM encrypted in RAM at all times using `SecureString` (`protect.cpp`)
- The in-memory key is **never stored** — it is derived fresh on every encrypt/decrypt call: `SHA256(get_machine_id() + "nice_key_is_nice" + passphrase)`
- After each use the key is immediately wiped via `secure_zero()` (`SecureZeroMemory` on Windows, `memset_s` on macOS, `explicit_bzero` on Linux)
- Plaintext exists only for microseconds during HTTP requests, then is wiped

**Device identity:**
- Every request carries a GUID derived from the machine's real physical MAC address (`device_mac.cpp`); the SAP / StoreAgent emulation is seeded with the same bytes
- Placeholder / virtual MACs (all-zero, `02:00:00:00:00:00`, broadcast, multicast, `AA:BB:CC:DD:EE:FF`) are rejected so signing stays consistent — see notes on macOS below

**`--keychain-passphrase`:**
- Optional second factor on top of machine binding — use the same value on every command after login
- Without it, machine binding alone protects the account file

---

## Dependencies

| Dependency | Purpose |
|------------|---------|
| libcurl | HTTPS networking (Schannel on Windows, OpenSSL elsewhere) |
| OpenSSL | AES-256-GCM, SHA-256, PBKDF2, HMAC |
| nlohmann-json | iTunes Search/Lookup JSON parsing |
| Unicorn Engine | x86-64 sandbox for SAP signing / kbsync / .pkg decryption |
| minizip *(optional)* | IPA repacking (falls back to a plain copy if absent) |

The SAP asset dylibs are not a package — they ship in `sap_assets/` in the repo and are embedded at build time (objcopy on Linux, RC resources on Windows, or loaded from the folder in development builds).

---

## Building on Windows (Visual Studio 2022)

### Step 1 — Install vcpkg (once)

```cmd
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
setx VCPKG_ROOT C:\vcpkg
```

Restart your terminal after setting the variable.

### Step 2a — Dynamic build (default)

```cmd
C:\vcpkg\vcpkg install curl:x64-windows nlohmann-json:x64-windows minizip:x64-windows openssl:x64-windows unicorn:x64-windows

cmake -B build -G "Visual Studio 17 2022" -A x64 ^
      -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release
```

Output: `build\Release\ipatool.exe`
Requires `MSVCP140.dll` / `VCRUNTIME140.dll` on the target machine (included with the VS redistributable).

### Step 2b — Fully static build (no DLL dependencies)

```cmd
C:\vcpkg\vcpkg install curl:x64-windows-static nlohmann-json:x64-windows-static minizip:x64-windows-static openssl:x64-windows-static unicorn:x64-windows-static

rmdir /s /q build

cmake -B build -G "Visual Studio 17 2022" -A x64 ^
      -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake ^
      -DSTATIC_BUILD=ON ^
      -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release
```

Output: `build\Release\ipatool.exe` — depends only on permanent Windows system DLLs (`KERNEL32.dll`, `WS2_32.dll`, `CRYPT32.dll`, `ADVAPI32.dll`, …). No redistributables needed.

> **Note:** Always delete `build\` before switching between dynamic and static builds.
>
> **Performance:** the emulated FairPlay init is heavy. Build **Release**, not Debug, and use the **release** vcpkg triplet — a debug Unicorn is dramatically slower (kbsync generation can go from seconds to minutes).

### Step 3 (alternative) — Open in Visual Studio 2022 directly

1. **File → Open → Folder** — select the project folder
2. VS detects `CMakeLists.txt` automatically
3. **Project → CMake Settings** → add CMake variable `CMAKE_TOOLCHAIN_FILE` = `C:\vcpkg\scripts\buildsystems\vcpkg.cmake`
4. Save, let CMake configure, then **Build → Build All**

---

## Building on Windows (MSYS2 MinGW-w64 — single-file static)

Builds a **fully static, self-contained `ipatool.exe`** with GCC — no third-party
DLLs, runs on any Windows (incl. Windows 7). Unicorn is built by GCC here, so the
FairPlay emulation (kbsync) is much faster than an MSVC-built Unicorn.

From an **MSYS2 MINGW64** shell:

```sh
pacman -S mingw-w64-x86_64-{gcc,cmake,ninja,openssl,minizip,zlib,bzip2,nlohmann-json} perl

cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DSTATIC_BUILD=ON
cmake --build build
# Output: build/ipatool.exe
```

What the build does automatically:
- Builds a **minimal curl from source** using Windows' native **Schannel** TLS
  (`HTTP_ONLY`), so curl needs no OpenSSL and none of brotli/zstd/idn2/psl/libssh2/
  nghttp2/3/ngtcp2.
- Builds **Unicorn (x86-only) from source** with GCC → fast, static.
- Statically links `libcrypto` (for AES/SHA), minizip, zlib and bzip2, plus
  `-static -static-libgcc -static-libstdc++`.

`perl` is required only by curl's build. Verify the result is self-contained:

```sh
ldd build/ipatool.exe | grep -iv 'windows\|system32'   # should print nothing
```

---

## Building on Linux

### Dynamic build

```sh
sudo apt install libcurl4-openssl-dev nlohmann-json3-dev libminizip-dev libssl-dev libunicorn-dev

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
# Output: build/ipatool
```

### Fully static build

```sh
sudo apt install libssl-dev libminizip-dev zlib1g-dev libunicorn-dev

cmake -B build -DCMAKE_BUILD_TYPE=Release -DSTATIC_BUILD=ON
cmake --build build
strip build/ipatool
# Output: build/ipatool
```

The static build compiles curl from source (HTTPS-only) via CMake `ExternalProject_Add`.
Verify with `ldd build/ipatool` — should show only `linux-vdso.so.1`, `libc.so.6`, `ld-linux-x86-64.so.2` (plus libunicorn if a static one wasn't found).

---

## Building on macOS

```sh
brew install curl nlohmann-json minizip openssl@3 unicorn

cmake -B build -DCMAKE_BUILD_TYPE=Release \
      -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3) \
      -DOPENSSL_USE_STATIC_LIBS=TRUE
cmake --build build
```

IOKit and CoreFoundation are built into macOS — no extra dependencies needed for machine ID.

### Native arm64 build (Apple silicon)

```sh
brew install openssl@3 minizip nlohmann-json unicorn pkg-config

cmake -B build -DCMAKE_BUILD_TYPE=Release \
      -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3) \
      -DCMAKE_OSX_ARCHITECTURES=arm64
cmake --build build
```

> This dynamic build targets the machine it's built on, so no
> `-DCMAKE_OSX_DEPLOYMENT_TARGET` is set — it links against the Homebrew
> libraries as they are. (Set a deployment target only for the static builds
> below, which are meant to run on older macOS versions.)
>
> On Apple silicon, target **native arm64** rather than an Intel (x86-64) host
> binary. This is a CPU-architecture choice, independent of the dynamic-vs-static
> options below. Unicorn emulates the x86-64 guest dylibs regardless of the host
> architecture, so an Intel host binary buys nothing — and run under Rosetta it
> double-emulates Unicorn's JIT and is many times slower. (On a real Intel Mac,
> use the Intel section below instead.)

### Static build (Apple silicon, arm64)

```sh
brew install nlohmann-json unicorn pkg-config

cmake -B build -DCMAKE_BUILD_TYPE=Release -DSTATIC_BUILD=ON \
      -DCMAKE_OSX_ARCHITECTURES=arm64 \
      -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0
cmake --build build
```

`11.0` is the oldest macOS that runs on Apple silicon, so this binary runs on
every Apple silicon Mac. The deployment target no longer affects text
formatting (the project uses its own `ipt::format()`, not `std::format`), so
you may raise or lower it freely within Apple silicon's supported range.

> **OpenSSL and minizip are built from source** for the static build, targeting
> the same arch and deployment target, so Homebrew's `openssl@3` and `minizip`
> are *not* needed (nor is `-DOPENSSL_ROOT_DIR`). This avoids Homebrew's
> bottles — compiled for the build machine's macOS — producing "built for newer
> macOS version" linker warnings and an unclean `minos`. The first configure
> downloads and compiles them (a few minutes, cached afterwards); override the
> versions with `-DOPENSSL_VERSION=<x.y.z>` / `-DZLIB_VERSION=<x.y.z>` if
> desired. minizip links against the system `libz` (present on every Mac).

### Static build on macOS Catalina (Intel)

```sh
brew install nlohmann-json unicorn pkg-config

cmake -B build -DCMAKE_BUILD_TYPE=Release -DSTATIC_BUILD=ON \
      -DCMAKE_OSX_ARCHITECTURES=x86_64 \
      -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15
cmake --build build
```

CMake downloads and builds a minimal curl from source (HTTPS only) and statically links it with OpenSSL and minizip. System frameworks (`IOKit`, `CoreFoundation`, `SystemConfiguration`, `CoreServices`) and `libz` remain dynamic — they ship with every Mac. Run `otool -L build/ipatool` to confirm.

---

## Usage

```
ipatool [global flags] <command> [flags]

Commands:
  auth login            Authenticate with the App Store
  auth info             Show currently saved account info
  auth revoke           Delete saved credentials
  search                Search for apps on the App Store
  purchase              Acquire a free app license
  download              Download an app IPA / macOS pkg
  list-versions         List available versions of an app
  get-version-metadata  Get metadata for a specific app version
  kbsync                Generate the kbsync blob locally (diagnostic; no request to Apple)

Global flags:
  --format text|json        Output format: human-readable text (default) or JSON
  --keychain-passphrase     Optional additional passphrase for account file encryption
  --debug                   Print full request/response dumps (headers + body; secrets masked)

download flags:
  -b / --bundle-id          Bundle identifier of the app
  -i / --app-id             Numeric App Store ID (skips iTunes lookup)
  -o / --output             Output file or directory path
  --external-version-id     Download a specific older version
  --purchase                Acquire license automatically if needed, then download

kbsync flags:
  --dsid DSID               Generate for an explicit DSID (diagnostic; ignores the cache)
  --refresh                 Force regeneration and refresh the cached blob
```

---

### Commands

#### `auth login`
```
ipatool auth login -e EMAIL -p PASSWORD [--auth-code CODE] [--keychain-passphrase PASSPHRASE]
```
Authenticates with the App Store and saves credentials to `~/.ipatool/account`. Every authenticate request is SAP-signed; login is refused if the bag has no usable SAP configuration. If 2FA is enabled and `--auth-code` is omitted, you are prompted interactively.

#### `auth info`
```
ipatool auth info [--keychain-passphrase PASSPHRASE]
```
Displays the name, email and storefront country of the saved account.

#### `auth revoke`
```
ipatool auth revoke
```
Deletes the saved credentials file (`~/.ipatool/account`).

#### `search`
```
ipatool search <term> [-l LIMIT] [--keychain-passphrase PASSPHRASE]
```
Searches the App Store. Default limit is 5.

#### `purchase`
```
ipatool purchase (-b BUNDLE_ID | -i APP_ID) [--keychain-passphrase PASSPHRASE]
```
Acquires a free license. Must be run once before downloading any app not already in your library.

#### `download`
```
ipatool download (-b BUNDLE_ID | -i APP_ID) [-o OUTPUT] [--external-version-id ID] [--purchase] [--keychain-passphrase PASSPHRASE]
```
Downloads an app as an `.ipa` (iOS) or decrypted `.pkg` (macOS).

- `-b` performs an iTunes lookup first; `-i` skips it and uses the numeric App Store ID directly
- The download first tries the `ent/download` stage using a cached/generated **kbsync**; if that does not serve the app it falls back to `volumeStore → redownload → updateProduct`
- `--external-version-id` downloads a specific older version (get IDs from `list-versions`)
- `-o` can be a file path or a directory; defaults to the current directory
- `--purchase` acquires the license if needed, then downloads
- Output filename format: `{bundleID}_{appID}_{version}.ipa`
- Resumable — re-running the same command continues an interrupted download
- iOS IPAs are patched to iTunes format (`iTunesMetadata.plist`, `iTunesArtwork`, sinf DRM token injected into `SC_Info/`); encrypted macOS `.pkg` files are decrypted via the StoreAgent sandbox

#### `list-versions`
```
ipatool list-versions (-b BUNDLE_ID | -i APP_ID) [--purchase] [--keychain-passphrase PASSPHRASE]
```
Returns all available external version IDs for an app.
- `--purchase` acquires the (free) license first if the app isn't yet in your library, then lists versions. Without it, an app you don't own returns a "must purchase" error.

#### `get-version-metadata`
```
ipatool get-version-metadata (-b BUNDLE_ID | -i APP_ID) --external-version-id ID [--keychain-passphrase PASSPHRASE]
```
Returns the display version string and release date for a specific version ID.

#### `kbsync`
```
ipatool kbsync [--dsid DSID] [--refresh] [--keychain-passphrase PASSPHRASE]
```
Diagnostic command that generates the kbsync blob locally through the FairPlay emulation — **no request is sent to Apple**. Prints length, header bytes and base64.

- With no `--dsid`: uses the saved account's DSID and the cached blob (`source=cache`); on a cache miss it generates once (~15–60 s+) and caches it in the account file
- `--refresh`: forces regeneration and updates the cache
- `--dsid N`: pure generation test for an explicit DSID — neither reads nor writes the cache
- A valid blob is a few hundred bytes and starts with `00 04 00 03`

> The first generation is slow because Apple's obfuscated `FairPlayGlobalContextInit` is heavy under emulation. The result is cached in the account file (bound to DSID + hardware, surviving token refreshes) and only regenerated when the server rejects it — so you pay this cost rarely.

---

## Typical workflow

```sh
# 1. Log in (credentials encrypted with machine binding)
ipatool auth login -e you@example.com -p yourpassword

# 2. Check saved account
ipatool auth info

# 3. Search for an app
ipatool search "minecraft" -l 5

# 4. Acquire license and download in one step
ipatool download -b com.mojang.minecraft-edu --purchase -o ~/Downloads

# 5. Or download by numeric app ID (skips the iTunes lookup)
ipatool download -i 1440285423 --purchase -o ~/Downloads

# 6. List available older versions, then download one
ipatool list-versions -b com.mojang.minecraft-edu
ipatool download -b com.mojang.minecraft-edu --external-version-id 123456789 -o ~/Downloads

# 7. Revoke saved credentials
ipatool auth revoke
```

---

## Output formats

Default output is human-readable text with colors (when stdout is a TTY):

```
10:32:15 INF name=John Appleseed email=john@example.com storefront=US success=true
```

With `--format json`:
```json
{"name":"John Appleseed","email":"john@example.com","storefront":"US","success":true}
```

(`auth login` and `auth info` include `storefront` — the account's country code.)

Colors are disabled automatically when output is piped. On Windows 7/8 the legacy Console API is used for colors; on Windows 10+ ANSI escape codes are used.

---

## Stored files

| File | Contents |
|------|----------|
| `~/.ipatool/account` | Apple ID credentials + cached kbsync — AES-256-GCM encrypted, machine-bound (format v2) |
| `~/.ipatool/cookies` | Session cookies (Netscape format, written by the tool itself) |

On Windows these are in `%USERPROFILE%\.ipatool\`. The account file is always encrypted; copy it to another machine and it cannot be decrypted — run `auth login` again.

---

## Notes

- If you move to a new machine or reinstall the OS, run `auth revoke` + `auth login` again
- Paid apps are not supported — only free apps and apps already in your account's library
- `purchase` must be run before `download` for any app not in your library
- Older versions obtained via `--external-version-id` may no longer be signed by Apple and might not install
- Session token expiry is handled automatically — the tool re-authenticates silently using stored credentials (2FA prompts once). The cached kbsync is preserved across such token refreshes
- `--debug` dumps full request/response headers and bodies; `X-Token` is masked and the login password is masked in the authenticate dump

---

## Source layout

**CLI & shared types**
- `main.cpp` — CLI entry point, argument parsing, all commands, account-file AES-GCM encryption, kbsync cache
- `ipatool.h` — shared types (`Account` incl. cached `kbsync`, `App`, `Sinf`), endpoints, error types
- `protect.cpp/.h` — `SecureString` in-memory encryption and `secure_zero`

**App Store protocol**
- `appstore.cpp/.h` — bag fetch, SAP-signed login, search/lookup, purchase, download (`ent/download` + `volumeStore → redownload → updateProduct`), list-versions, version metadata, storefront↔country table, iTunes JSON parsing
- `http_client.cpp/.h` — libcurl wrapper (GET/POST, resumable download, custom cookie file I/O via `CURLOPT_COOKIELIST`)
- `plist.cpp/.h` — Apple plist XML + binary encoder/decoder (no external deps)

**Device identity & crypto**
- `device_mac.cpp/.h` — stable physical MAC / GUID / hardware ID (IOKit `en0` on macOS, `GetIfTable2` on Windows, sysfs on Linux) with placeholder-MAC rejection
- `hwid.cpp/.h` — machine-ID derivation and PBKDF2 file-key derivation
- `aes.cpp/.h` — AES-256-GCM (OpenSSL)
- `sha2.cpp/.h` — SHA-256, HMAC, PBKDF2 (OpenSSL EVP)

**FairPlay emulation (Unicorn x86-64)**
- `SapSigner.cpp/.h` — SAP action-signature signer (init/exchange/sign), `SapBase64`, `LocalHardwareID`
- `SapMachine.cpp/.h` — Unicorn runtime for `CoreFP`/`CommerceCore`/`CommerceKit` and the syscall/library shims (`SapShims`)
- `StoreAgentMachine.cpp/.h` — Unicorn runtime for `storeagent`: `FairPlayGlobalContextInit`, `.pkg` chunk decryption, and `FairPlayKBSyncDataWithDSID` (kbsync)
- `MachImage.cpp/.h` — Mach-O 64 loader/relocator (segments, binds, rebases) for the sandbox
- `sap_embedded_assets.h` — accessor for the SAP dylibs embedded via objcopy (Linux/ELF)
- `sap_resources.h` — resource IDs for the SAP dylibs embedded as Windows RC data

**Misc**
- `compat_format.h` — dependency-free `ipt::format()` (`{}` / `{:#x}`) used for diagnostics; no `std::format` / fmtlib
- `CMakeLists.txt` — cross-platform build (vcpkg + static support + asset embedding)
- `sap_assets/` — Apple FairPlay dylibs embedded at build time (not tracked for redistribution)
```
