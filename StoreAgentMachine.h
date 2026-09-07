#pragma once
#include "MachImage.h"
#include "SapMachine.h"   // reuse SapShims

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <vector>

struct uc_struct;
typedef struct uc_struct uc_engine;

// ─────────────────────────────────────────────────────────────────────────────
//  StoreAgentMachine
//
//  Port of ipatool internal/sap/machine/storeagent.go.
//
//  Runs the Apple storeagent binary under Unicorn x86-64 alongside the
//  usual CoreFP/CommerceCore/CommerceKit dylibs to decrypt macOS .pkg files
//  purchased from the App Store.
//
//  Usage:
//      auto sa = StoreAgentMachine::Create(coreFP, commerceCore,
//                                          commerceKit, coreFPIcxs, storeagent);
//      auto globalCtx = sa->InitializeGlobal(hardwareID);  // raw MAC bytes
//      auto session   = sa->InitializeSession(globalCtx, dpInfo);
//      sa->DecryptChunk(session, data);   // in-place, 32 KB at a time
//      sa->CloseSession(session);
// ─────────────────────────────────────────────────────────────────────────────
class StoreAgentMachine {
public:
    static std::unique_ptr<StoreAgentMachine> Create(
        std::vector<uint8_t> coreFP,
        std::vector<uint8_t> commerceCore,
        std::vector<uint8_t> commerceKit,
        std::vector<uint8_t> coreFPIcxs,
        std::vector<uint8_t> storeAgent);

    ~StoreAgentMachine();

    // Step 1: initialize global context with raw hardware ID bytes.
    // Returns a uint32 context handle.
    uint32_t InitializeGlobal(std::span<const uint8_t> hardwareID);

    // Step 2: initialize a decryption session using dpInfo from the download Sinf.
    // Returns a uint64 session handle.
    uint64_t InitializeSession(uint32_t globalCtx,
                               std::span<const uint8_t> dpInfo);

    // Decrypt one chunk in-place (max kChunkSize bytes).
    void DecryptChunk(uint64_t session, std::span<uint8_t> data);

    // Close the session.
    void CloseSession(uint64_t session);

    static constexpr size_t kChunkSize = 0x8000; // 32 KB — matches Go storeAgentChunkSize

private:
    StoreAgentMachine() = default;

    // ── guest address space ───────────────────────────────────────────────────
    // SAP images share the same layout as in SapMachine
    static constexpr uint64_t kReturnAddr   = 0x0000000100000000ULL;
    static constexpr uint64_t kCoreFPBase   = 0x0000100000000000ULL;
    static constexpr uint64_t kCommerceBase = 0x0000100040000000ULL;
    static constexpr uint64_t kKitBase      = 0x0000100080000000ULL;
    static constexpr uint64_t kAgentBase    = 0x00001000c0000000ULL; // storeAgentBase
    static constexpr uint64_t kScratchBase  = 0x0000300000000000ULL;
    static constexpr uint64_t kScratchSize  = uint64_t(32) << 20;
    static constexpr uint64_t kHeapBase     = 0x0000400000000000ULL;
    static constexpr uint64_t kHeapSize     = uint64_t(64) << 20;
    static constexpr uint64_t kStackBase    = 0x0000500000000000ULL;
    static constexpr uint64_t kStackSize    = uint64_t(8)  << 20;
    static constexpr uint64_t kStackEnd     = kStackBase + kStackSize;
    static constexpr uint64_t kPageSize     = 0x1000;

    // ── entry points (hardcoded offsets from storeagent.go) ──────────────────
    static constexpr uint64_t kGlobalInit   = kAgentBase + 0x0c5fc0;
    static constexpr uint64_t kSessionInit  = kAgentBase + 0x0debd0;
    static constexpr uint64_t kDecryptEntry = kAgentBase + 0x0ee700;
    static constexpr uint64_t kSessionClose = kAgentBase + 0x1212d0;

    // SC Info path expected by storeagent (shimmed via open())
    static constexpr const char* kSCInfoPath = "/Users/Shared/SC Info";

    // ── helpers ───────────────────────────────────────────────────────────────
    static std::vector<uint8_t> HardwareBlock(std::span<const uint8_t> id);
    uint64_t Invoke(uint64_t fn, std::initializer_list<uint64_t> args);
    uint64_t Scratch(const void* data, uint64_t len);
    uint64_t Scratch(uint64_t len) { return Scratch(nullptr, len); }
    void     ClearScratch();
    void     BeginCall() { /* scratch reset happens in ClearScratch */ }
    uint64_t GuestRead64(uint64_t addr);
    uint32_t GuestRead32(uint64_t addr);

    uc_engine*                uc_            = nullptr;
    std::unique_ptr<SapShims> shims_;
    uint64_t                  scratchCursor_ = 0;
};
