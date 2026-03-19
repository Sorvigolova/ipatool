# ipatool-cpp

A C++17 port of [ipatool](https://github.com/majd/ipatool) — a command-line tool for downloading iOS app packages from the App Store.  
Uses **libcurl** for networking. Builds on **Windows (VS 2022)**, Linux, and macOS with optional fully static binaries.

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
- **Windows**: `SHA256(ProductId + MachineGuid)` — from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` and `HKLM\SOFTWARE\Microsoft\Cryptography`. Inspired by how iTunes binds its own SC Info store to the Windows installation.
- **Linux**: `SHA256(machine-id + product_uuid)` — from `/etc/machine-id` and `/sys/class/dmi/id/product_uuid`
- **macOS**: `SHA256(IOPlatformSerialNumber + IOPlatformUUID)` — via IOKit

**In-memory protection:**
- Sensitive fields (`passwordToken`, `password`) are AES-256-GCM encrypted in RAM at all times using `SecureString`
- The in-memory key is **never stored** — it is derived fresh on every encrypt/decrypt call: `SHA256(get_machine_id() + "nice_key_is_nice" + passphrase)`
- After each use the key is immediately wiped with `SecureZeroMemory`/`explicit_bzero`
- Plaintext exists only for microseconds during HTTP requests, then wiped
- Only `g_passphrase` (the user-provided passphrase, which the user already knows) is kept in memory

**`--keychain-passphrase`:**
- Optional second factor on top of machine binding
- Use the same value on every command after login
- Without it, machine binding alone protects the account file

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
C:\vcpkg\vcpkg install curl:x64-windows nlohmann-json:x64-windows minizip:x64-windows openssl:x64-windows

cmake -B build -G "Visual Studio 17 2022" -A x64 ^
      -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release
```

Output: `build\Release\ipatool.exe`  
Requires `MSVCP140.dll` / `VCRUNTIME140.dll` on the target machine (included with the VS redistributable).

### Step 2b — Fully static build (no DLL dependencies)

```cmd
C:\vcpkg\vcpkg install curl:x64-windows-static nlohmann-json:x64-windows-static minizip:x64-windows-static openssl:x64-windows-static

rmdir /s /q build

cmake -B build -G "Visual Studio 17 2022" -A x64 ^
      -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake ^
      -DSTATIC_BUILD=ON
cmake --build build --config Release
```

Output: `build\Release\ipatool.exe`

The resulting binary only depends on permanent Windows system DLLs (`KERNEL32.dll`, `WS2_32.dll`, `CRYPT32.dll`, `ADVAPI32.dll`, etc.) — no redistributables, no extra DLLs needed. Runs on any Windows machine.

> **Note:** Always delete `build\` before switching between dynamic and static builds.

### Step 3 (alternative) — Open in Visual Studio 2022 directly

1. **File → Open → Folder** — select the project folder
2. VS detects `CMakeLists.txt` automatically
3. Go to **Project → CMake Settings**
4. Add CMake variable: `CMAKE_TOOLCHAIN_FILE` = `C:\vcpkg\scripts\buildsystems\vcpkg.cmake`
5. Save, let CMake configure, then **Build → Build All**

---

## Building on Linux

### Dynamic build

```sh
sudo apt install libcurl4-openssl-dev nlohmann-json3-dev libminizip-dev libssl-dev

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
# Output: build/ipatool
```

### Fully static build

```sh
sudo apt install libssl-dev libminizip-dev zlib1g-dev

cmake -B build -DCMAKE_BUILD_TYPE=Release -DSTATIC_BUILD=ON
cmake --build build
strip build/ipatool
# Output: build/ipatool — fully statically linked
```

The static build compiles curl from source (HTTPS-only) via CMake `ExternalProject_Add`.  
Only `libc.so.6` remains dynamic — standard and expected on Linux.

Verify with `ldd build/ipatool` — should show only `linux-vdso.so.1`, `libc.so.6`, `ld-linux-x86-64.so.2`.

---

## Building on macOS

```sh
brew install curl nlohmann-json minizip openssl

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

IOKit and CoreFoundation are built into macOS — no extra dependencies needed for machine ID.

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
  download              Download an app IPA
  list-versions         List available versions of an app
  get-version-metadata  Get metadata for a specific app version

Global flags:
  --format text|json        Output format: human-readable text (default) or JSON
  --keychain-passphrase     Optional additional passphrase for account file encryption
  --debug                   Print raw server responses for troubleshooting

download flags:
  -b / --bundle-id          Bundle identifier of the app
  -i / --app-id             Numeric App Store ID (skips iTunes lookup)
  -o / --output             Output file or directory path
  --external-version-id     Download a specific older version
  --purchase                Acquire license automatically if needed, then download
```

---

### Commands

#### `auth login`
```
ipatool auth login -e EMAIL -p PASSWORD [--auth-code CODE] [--keychain-passphrase PASSPHRASE]
```
Authenticates with the App Store and saves credentials to `~/.ipatool/account`.

- Credentials are always encrypted — bound to the current machine
- If the account has 2FA enabled and `--auth-code` is omitted, you will be prompted interactively
- `--keychain-passphrase` adds an optional second factor on top of machine binding

#### `auth info`
```
ipatool auth info [--keychain-passphrase PASSPHRASE]
```
Displays the name and email of the currently saved account.

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
ipatool purchase -b BUNDLE_ID [--keychain-passphrase PASSPHRASE]
```
Acquires a free license for an app. Must be run once before downloading any app not already in your library.

#### `download`
```
ipatool download (-b BUNDLE_ID | -i APP_ID) [-o OUTPUT] [--external-version-id ID] [--purchase] [--keychain-passphrase PASSPHRASE]
```
Downloads an app as an `.ipa` file.

- `-b` performs an iTunes lookup first; `-i` skips it and uses the numeric App Store ID directly
- `--external-version-id` downloads a specific older version (get IDs from `list-versions`)
- `-o` can be a file path or a directory; defaults to the current directory
- `--purchase` automatically acquires the app license if needed, then downloads
- Output filename format: `{bundleID}_{appID}_{version}.ipa`
- A progress bar is shown on TTY: `Downloading:  42% |          | (50/119 MB, 8.3 MB/s)`
- Download is resumable — if interrupted, re-running the same command continues from where it stopped
- The IPA is patched to match the iTunes format:
  - `iTunesMetadata.plist` — written to zip root with full account info, purchase date, and `com.apple.iTunesStore.downloadInfo`
  - `iTunesArtwork` — app icon (600×600 PNG, no extension) written to zip root
  - Sinf DRM token injected into `Payload/{App}.app/SC_Info/`

#### `list-versions`
```
ipatool list-versions (-b BUNDLE_ID | -i APP_ID) [--keychain-passphrase PASSPHRASE]
```
Returns all available version IDs for an app.

#### `get-version-metadata`
```
ipatool get-version-metadata (-b BUNDLE_ID | -i APP_ID) --external-version-id ID [--keychain-passphrase PASSPHRASE]
```
Returns the display version string and release date for a specific version ID.

---

## Typical workflow

```sh
# 1. Log in (credentials encrypted with machine binding)
ipatool auth login -e you@example.com -p yourpassword

# 1b. With optional extra passphrase
ipatool auth login -e you@example.com -p yourpassword --keychain-passphrase mysecret

# 2. Check saved account
ipatool auth info

# 3. Search for an app
ipatool search "minecraft" -l 5

# 4a. Acquire the license separately, then download
ipatool purchase -b com.mojang.minecraft-edu
ipatool download -b com.mojang.minecraft-edu -o ~/Downloads

# 4b. Or acquire license and download in one step
ipatool download -b com.mojang.minecraft-edu --purchase -o ~/Downloads

# 5. Download by numeric app ID (skips the iTunes lookup)
ipatool download -i 1440285423 --purchase -o ~/Downloads

# 6. List available older versions
ipatool list-versions -b com.mojang.minecraft-edu

# 7. Download a specific older version
ipatool download -b com.mojang.minecraft-edu --external-version-id 123456789 -o ~/Downloads

# 8. Revoke saved credentials
ipatool auth revoke
```

---

## Output formats

By default output uses human-readable text with colors (when stdout is a TTY):

```
10:32:15 INF name=John Appleseed email=john@example.com success=true
```

With `--format json`:
```json
{"name":"John Appleseed","email":"john@example.com","success":true}
```

Colors are automatically disabled when output is piped or redirected.  
On Windows 7/8 the legacy Console API is used for colors; on Windows 10+ ANSI escape codes are used.

---

## Stored files

| File | Contents |
|------|----------|
| `~/.ipatool/account` | Apple ID credentials — AES-256-GCM encrypted, machine-bound (format v2) |
| `~/.ipatool/cookies` | Session cookies (libcurl cookie jar, required for download) |

On Windows these are in `%USERPROFILE%\.ipatool\`.

The account file is always encrypted. If you copy it to another machine or reinstall the OS, it cannot be decrypted — run `auth login` again on the new machine.

---

## Notes

- If you move to a new machine or reinstall the OS, run `auth revoke` + `auth login` again
- Paid apps are not supported — only free apps and apps already purchased on your account
- `purchase` must be run before `download` for any app not in your library
- `--keychain-passphrase` is optional but adds a second factor — use the same value on every command
- Older versions obtained via `--external-version-id` may no longer be signed by Apple and might not install
- Session token expiry is handled automatically — the tool re-authenticates silently using stored credentials. If 2FA is required, you will be prompted once

---

## File layout

```
ipatool-cpp/
├── main.cpp           ← CLI entry point, arg parsing, all commands, file encryption
├── ipatool.h          ← Shared types (Account, App, Sinf), SecureString, in-memory encryption
├── hwid.h             ← Machine ID derivation (Windows registry, Linux /etc, macOS IOKit)
├── http_client.h      ← libcurl wrapper (GET, POST, resumable download, cookie jar)
├── plist.h            ← Apple plist XML+binary encoder/decoder (no external deps)
├── json_helpers.h     ← nlohmann/json helpers for iTunes search/lookup API
├── appstore.h         ← All App Store API logic (login, search, purchase, download)
├── storefront.h       ← Country code ↔ storefront ID map (130 entries)
├── CMakeLists.txt     ← Cross-platform CMake build (vcpkg + static support)
└── README.md
```
