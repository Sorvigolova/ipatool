#pragma once
// Symbols injected by objcopy --input binary (Linux/ELF builds).
// Generated when cmake detects objcopy and SAP_ASSETS_EMBEDDED is defined.
// Each symbol pair brackets the raw bytes of the asset file.
#ifdef SAP_ASSETS_EMBEDDED
#include <cstdint>

extern "C" {
    // CoreFP (~29 MB)
    extern const uint8_t _binary_CoreFP_start[];
    extern const uint8_t _binary_CoreFP_end[];
    // CommerceCore (~200 KB)
    extern const uint8_t _binary_CommerceCore_start[];
    extern const uint8_t _binary_CommerceCore_end[];
    // CommerceKit (~3 MB)
    extern const uint8_t _binary_CommerceKit_start[];
    extern const uint8_t _binary_CommerceKit_end[];
    // CoreFP.icxs (~5 MB) — dots → underscores in symbol name
    extern const uint8_t _binary_CoreFP_icxs_start[];
    extern const uint8_t _binary_CoreFP_icxs_end[];
    // storeagent (~2.5 MB)
    extern const uint8_t _binary_storeagent_start[];
    extern const uint8_t _binary_storeagent_end[];
}

// Convenience: span-like view of each embedded asset
#include <cstddef>
struct EmbeddedAsset { const uint8_t* data; size_t size; };

inline EmbeddedAsset embedded_CoreFP()       { return {_binary_CoreFP_start,       (size_t)(_binary_CoreFP_end       - _binary_CoreFP_start      )}; }
inline EmbeddedAsset embedded_CommerceCore() { return {_binary_CommerceCore_start, (size_t)(_binary_CommerceCore_end - _binary_CommerceCore_start )}; }
inline EmbeddedAsset embedded_CommerceKit()  { return {_binary_CommerceKit_start,  (size_t)(_binary_CommerceKit_end  - _binary_CommerceKit_start  )}; }
inline EmbeddedAsset embedded_CoreFP_icxs() { return {_binary_CoreFP_icxs_start,  (size_t)(_binary_CoreFP_icxs_end  - _binary_CoreFP_icxs_start  )}; }
inline EmbeddedAsset embedded_storeagent()  { return {_binary_storeagent_start,    (size_t)(_binary_storeagent_end   - _binary_storeagent_start   )}; }
#endif // SAP_ASSETS_EMBEDDED
