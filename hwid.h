#pragma once
// hwid.h — Cross-platform machine ID derivation for account file encryption.
//
// Returns a stable, machine-bound identifier used as input to the file
// encryption key derivation: PBKDF2(machine_id + FILE_KEY_SALT + passphrase, ...)
// Also called fresh on every in-memory encrypt/decrypt via g_machine_id_fn.
//
// Windows : SHA256(ProductId + MachineGuid)
//           ProductId  — HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
//           MachineGuid — HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
//           Inspired by iTunes SC Info binding to the Windows product key.
// Linux   : SHA256(machine-id + product_uuid)
//           /etc/machine-id + /sys/class/dmi/id/product_uuid
// macOS   : SHA256(IOPlatformSerialNumber + IOPlatformUUID) via IOKit
//
// Declarations only — see hwid.cpp for implementations.

#include <string>

// Stable, machine-bound identifier (platform-specific derivation, see above).
std::string get_machine_id();

extern const char* FILE_KEY_SALT;

// Derive 32-byte file encryption key:
// PBKDF2-SHA256(machine_id + FILE_KEY_SALT + passphrase, salt, 100000, 32)
bool derive_key_from_machine(const std::string& machine_id,
                             const std::string& passphrase,
                             const unsigned char* salt, int salt_len,
                             unsigned char* key_out);
