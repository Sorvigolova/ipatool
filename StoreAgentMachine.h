#pragma once
#include "MachImage.h"
#include "SapMachine.h"   // reuse SapShims

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
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
    // coreADI is optional: pass the 10.9 CoreADI.framework/CoreADI binary
    // (fat or x86-64) to enable the Adi* calls below; leave it empty otherwise.
    static std::unique_ptr<StoreAgentMachine> Create(
        std::vector<uint8_t> coreFP,
        std::vector<uint8_t> commerceCore,
        std::vector<uint8_t> commerceKit,
        std::vector<uint8_t> coreFPIcxs,
        std::vector<uint8_t> storeAgent,
        std::vector<uint8_t> coreADI = {});

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

    // kbsync blob for an account DSID — FairPlayKBSyncDataWithDSID, the
    // storeagent function behind -[… _kbSyncDataWithDSID:]. Takes the context
    // from InitializeGlobal(); no keybag in "SC Info" is needed.
    std::vector<uint8_t> KBSyncData(uint32_t globalCtx, uint64_t dsid);

    // ── ADI (anisette "machine data", 10.9 Mac App Store flavour) ─────────────
    //
    // storeagent never calls CoreADI directly: it dlopen()s
    // CoreADI.framework, dlsym()s its two exports (cvu8io98wun, vdfut768ig)
    // and talks to them through a serialising marshaller. The functions below
    // call storeagent's own C-ABI wrappers around that marshaller — the same
    // ones -[ADIProvisioningOperation run] and -[ADIController
    // _generateOTPOnCurrentThreadForDSID:withHandler:] use.
    //
    // Server protocol (response header x-apple-md-action / x-apple-md-data):
    //   "RP" → AdiErase(dsid), retry the request without MD headers
    //   "SP" → AdiStartProvisioning(dsid, b64decode(md-data)) → POST
    //          {clientData, kbsync, guid, dsId} to bag md-finish-provisioning
    //          → AdiEndProvisioning(session, settingInfo, transportKey)
    //          → ImportKeyBag(globalCtx, keybag) if the reply carries one
    //   "SM" → AdiSynchronize(dsid, b64decode(md-data)) → POST
    //          {clientData, machineId, dsId} to bag md-sync-machine
    //          → the reply's syncState goes out as X-Apple-MD-S from then on
    //          (-[ADIMachineSyncOperation run], -[ADIController
    //          _mutateURLRequest:onCurrentThreadWithDSID:])
    bool HasADI() const { return adiLoaded_; }

    struct AdiStartResult { std::vector<uint8_t> clientData; uint32_t session = 0; };
    AdiStartResult AdiStartProvisioning(uint64_t dsid, std::span<const uint8_t> serverData);

    void AdiEndProvisioning(uint32_t session,
                            std::span<const uint8_t> settingInfo,
                            std::span<const uint8_t> transportKey);

    // X-Apple-MD-M (machine ID) and X-Apple-MD (one-time password).
    struct AdiOTP { std::vector<uint8_t> machineID; std::vector<uint8_t> otp; };
    // nullopt (with status) when the DSID is not provisioned — storeagent
    // then simply omits the MD headers.
    std::optional<AdiOTP> AdiRequestOTP(uint64_t dsid, int32_t* status = nullptr);

    // Drop the provisioning for a DSID (server action "RP"). Returns status.
    int32_t AdiErase(uint64_t dsid);

    // Machine sync (server action "SM"): x-apple-md-data in, the clientData /
    // machineId pair for md-sync-machine out. Throws on a non-zero status.
    struct AdiSyncResult { std::vector<uint8_t> clientData; std::vector<uint8_t> machineId; };
    AdiSyncResult AdiSynchronize(uint64_t dsid, std::span<const uint8_t> serverData);

    // syncState from the md-sync-machine reply (sent as X-Apple-MD-S). Kept in
    // the exported ADI state, outside the guest-visible virtual roots.
    std::vector<uint8_t> GetSyncState() const;
    void                 SetSyncState(std::vector<uint8_t> state);

    // FairPlay keybag from a provisioning / authorization reply.
    // Returns the FairPlay status (0 = imported).
    int32_t ImportKeyBag(uint32_t globalCtx, std::span<const uint8_t> keyBag);

    // Opaque ADI state (CoreADI's on-disk database + host UUID). Persist it
    // after every Adi* call and hand it back to the next machine; without it
    // every run starts unprovisioned. Import before the first Adi* call.
    std::vector<uint8_t> ExportAdiState() const;
    void                 ImportAdiState(std::span<const uint8_t> state);

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
    static constexpr uint64_t kCoreADIBase  = 0x0000100100000000ULL;
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
    // (ctx, dsid, 0, 1, &outPtr, &outLen) -> 0 on success
    static constexpr uint64_t kKBSyncData   = kAgentBase + 0x0c93c0;
    // (globalCtx, keybag, len) — FairPlay keybag import used by
    // -[ADIProvisioningOperation run] ("Imported FP keybag from machine provisioning")
    static constexpr uint64_t kImportKeyBag = kAgentBase + 0x0d5ce0;

    // ADI wrappers (storeagent 10.9, Pisa-215.1), all return int32 status:
    //   start (u64 dsid, u8* spim, u32 len, u8** cpim, u32* cpimLen, u32* session)
    //   end   (u32 session, u8* settingInfo, u32 len, u8* transportKey, u32 len)
    //   otp   (u64 dsid, u8** mid, u32* midLen, u8** otp, u32* otpLen)
    //   erase (u64 dsid)
    //   sync  (u64 dsid, u8* sim, u32 len, u8** machineId, u32* len,
    //          u8** clientData, u32* len)  — 7th argument on the stack
    static constexpr uint64_t kAdiStart     = kAgentBase + 0x1a8cf0;
    static constexpr uint64_t kAdiEnd       = kAgentBase + 0x1a9880;
    static constexpr uint64_t kAdiOTP       = kAgentBase + 0x1aa100;
    static constexpr uint64_t kAdiErase     = kAgentBase + 0x1aed40;
    static constexpr uint64_t kAdiSync      = kAgentBase + 0x1ab240;
    // Host-side slot for syncState inside the virtual-file map (not under a
    // virtual root, so guest code never sees it).
    static constexpr const char* kSyncStatePath = "/ipatool/adi-sync-state";

    // dlopen() path storeagent uses for CoreADI (plain string at 0x10021b310)
    static constexpr const char* kCoreADIPath =
        "/System/Library/PrivateFrameworks/CoreADI.framework/CoreADI";
    // Directory trees guest code may create files in (virtual FS roots):
    // CoreADI's adi.pb and FairPlay's keybag store (SC Info.sidb/.sidd/.sidn),
    // which ImportKeyBag() writes after provisioning.
    static constexpr const char* kAdiVirtualRoot    = "/Users/Shared/adi";
    static constexpr const char* kSCInfoVirtualRoot = "/Users/Shared/SC Info";

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
    std::vector<uint8_t> GuestReadBytes(uint64_t addr, uint32_t len);
    void     RequireADI() const;

    uc_engine*                uc_            = nullptr;
    bool                      adiLoaded_     = false;
    std::array<uint8_t, 16>   hostUUID_{};
    std::unique_ptr<SapShims> shims_;
    uint64_t                  scratchCursor_ = 0;
    uint64_t                  disposeFn_     = 0; // CommerceKit FairPlayDisposeStorage
};
