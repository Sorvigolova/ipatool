#include "StoreAgentMachine.h"
#include "SapMachine.h"

#include <unicorn/unicorn.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include "compat_format.h"
#include <random>
#include <stdexcept>

// x86-64 SysV arg registers — same as SapMachine
static constexpr int kArgRegs[6] = {
    UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
    UC_X86_REG_RCX, UC_X86_REG_R8,  UC_X86_REG_R9,
};
// No wall-clock timeout on the guest. FairPlay's obfuscated global-context init
// is legitimately heavy — ~15 s on fast native Unicorn, over a minute on a
// slower build, and several minutes on old hardware — so any fixed deadline
// eventually aborts a still-correct computation. Emulation stops when IP hits
// kReturnAddr; genuine faults are still caught (uc_err + shim HasFault). The
// trade-off: a true runaway would run until the user interrupts it (Ctrl+C).
static constexpr uint64_t kTimeoutUs = 0ULL;

static inline void UCK(uc_err e, const char* w) {
    if (e != UC_ERR_OK)
        throw std::runtime_error(ipt::format("{}: {}", w, uc_strerror(e)));
}
static inline uint64_t AlignUp(uint64_t v, uint64_t a) { return (v+a-1)&~(a-1); }

// ═══════════════════════════════════════════════════════════════════════════
//  Create
// ═══════════════════════════════════════════════════════════════════════════

std::unique_ptr<StoreAgentMachine> StoreAgentMachine::Create(
    std::vector<uint8_t> coreFP,
    std::vector<uint8_t> commerceCore,
    std::vector<uint8_t> commerceKit,
    std::vector<uint8_t> coreFPIcxs,
    std::vector<uint8_t> storeAgent,
    std::vector<uint8_t> coreADI)
{
    auto m = std::unique_ptr<StoreAgentMachine>(new StoreAgentMachine());

    // 1. Unicorn x86-64
    UCK(uc_open(UC_ARCH_X86, UC_MODE_64, &m->uc_), "uc_open");

    // 2. Map memory regions
    for (auto [addr, size] : std::initializer_list<std::pair<uint64_t,uint64_t>>{
        { kReturnAddr,  kPageSize    },
        { kScratchBase, kScratchSize },
        { kHeapBase,    kHeapSize    },
        { kStackBase,   kStackSize   },
    }) UCK(uc_mem_map(m->uc_, addr, size, UC_PROT_ALL), "map region");

    uint8_t hlt = 0xF4;
    UCK(uc_mem_write(m->uc_, kReturnAddr, &hlt, 1), "write HLT");

    // 3. Open all images
    auto imgCoreFP       = MachImage::Open("CoreFP",       std::move(coreFP));
    auto imgCommerceCore = MachImage::Open("CommerceCore", std::move(commerceCore));
    auto imgCommerceKit  = MachImage::Open("CommerceKit",  std::move(commerceKit));
    auto imgAgent        = MachImage::Open("storeagent",   std::move(storeAgent));
    std::unique_ptr<MachImage> imgCoreADI;
    if (!coreADI.empty())
        imgCoreADI = MachImage::Open("CoreADI", std::move(coreADI));

    // 4. CoreFP named exports for the shim resolver
    static const char* kCoreFPExportNames[] = {
        "_WIn9UJ86JKdV4dM", "_X46O5IeS",    "_YlCJ3lg",
        "_dku592fbFAj",     "_fdjkDSAFjklaf2s", "_lxpgvVMLd0S7uRl",
    };
    std::unordered_map<std::string, uint64_t> coreExports;
    for (const char* n : kCoreFPExportNames) {
        try { coreExports[n] = imgCoreFP->Export(n, kCoreFPBase); } catch (...) {}
    }
    try { coreExports["_get_mac_address"] =
              imgCommerceCore->Export("_get_mac_address", kCommerceBase); } catch (...) {}

    // 5. Shims — reuse SapShims infrastructure
    m->shims_ = std::make_unique<SapShims>(m->uc_, std::move(coreExports), std::move(coreFPIcxs));
    m->shims_->SetHeap(kHeapBase, kHeapSize);

    // 6. Resolver
    auto resolver = [&](std::string_view name) -> uint64_t {
        // storeagent-specific zero-return aliases (from storeagent.go)
        static const char* kAgentAliases[] = {
            "_pthread_rwlock_rdlock", "_pthread_rwlock_rdlock$UNIX2003",
            "_pthread_mutex_init",    "_pthread_mutex_destroy",
            "_pthread_rwlock_destroy",
        };
        for (const char* a : kAgentAliases)
            if (name == a) return m->shims_->Resolve(name); // already zero-return in shims
        return m->shims_->Resolve(name);
    };

    // 7. Relocate all images
    imgCoreFP      ->Relocate(kCoreFPBase,   resolver);
    imgCommerceCore->Relocate(kCommerceBase, resolver);
    imgCommerceKit ->Relocate(kKitBase,      resolver);
    imgAgent       ->Relocate(kAgentBase,    resolver);
    if (imgCoreADI)
        imgCoreADI ->Relocate(kCoreADIBase,  resolver);

    // 8. Load into Unicorn
    imgCoreFP      ->Load(m->uc_);
    imgCommerceCore->Load(m->uc_);
    imgCommerceKit ->Load(m->uc_);
    imgAgent       ->Load(m->uc_);

    // 8b. CoreADI — reachable only through storeagent's dlopen/dlsym
    if (imgCoreADI) {
        imgCoreADI->Load(m->uc_);
        std::unordered_map<std::string, uint64_t> adiExports;
        for (const char* n : { "_cvu8io98wun", "_vdfut768ig" })
            adiExports[n] = imgCoreADI->Export(n, kCoreADIBase);   // throws if missing
        m->shims_->RegisterDylib(kCoreADIPath, std::move(adiExports));
        m->shims_->SetVirtualRoots({ kAdiVirtualRoot, kSCInfoVirtualRoot });

        // Fresh identity until ImportAdiState() replaces it.
        std::array<uint8_t, 16> uuid{};
        std::random_device rd;
        for (auto& b : uuid) b = static_cast<uint8_t>(rd());
        uuid[6] = static_cast<uint8_t>((uuid[6] & 0x0F) | 0x40);   // RFC 4122 v4
        uuid[8] = static_cast<uint8_t>((uuid[8] & 0x3F) | 0x80);
        m->shims_->SetHostUUID(uuid);
        m->hostUUID_  = uuid;
        m->adiLoaded_ = true;
    }

    // FairPlayDisposeStorage — frees buffers returned by FairPlay (kbsync)
    try { m->disposeFn_ = imgCommerceKit->Export("_jEHf8Xzsv8K", kKitBase); } catch (...) {}

    return m;
}

StoreAgentMachine::~StoreAgentMachine() {
    shims_.reset();
    if (uc_) uc_close(uc_);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Invoke
// ═══════════════════════════════════════════════════════════════════════════

uint64_t StoreAgentMachine::Invoke(uint64_t fn, std::initializer_list<uint64_t> args) {
    if (!fn) throw std::runtime_error("StoreAgent entry point is zero");

    shims_->BeforeInvoke();

    int ri = 0;
    for (uint64_t a : args)
        if (ri < 6) UCK(uc_reg_write(uc_, kArgRegs[ri++], &a), "write arg");

    // SysV: arguments 7+ go on the stack right above the return address.
    // RSP is 16n+8 at entry (as if after a CALL).
    const uint64_t extra = args.size() > 6 ? args.size() - 6 : 0;
    uint64_t rsp = kStackEnd - (extra + 1) * 8;
    if (rsp % 16 != 8) rsp -= 8;
    UCK(uc_mem_write(uc_, rsp, &kReturnAddr, 8), "push return addr");
    {
        size_t i = 0;
        for (uint64_t a : args) {
            if (i >= 6)
                UCK(uc_mem_write(uc_, rsp + 8 * (i - 5), &a, 8), "push stack arg");
            ++i;
        }
    }
    UCK(uc_reg_write(uc_, UC_X86_REG_RSP, &rsp), "write RSP");

    uc_err err = uc_emu_start(uc_, fn, kReturnAddr, kTimeoutUs, 0);
    if (err != UC_ERR_OK && !shims_->HasFault())
        throw std::runtime_error(ipt::format("uc_emu_start: {}", uc_strerror(err)));
    if (shims_->HasFault())
        throw std::runtime_error(shims_->TakeFault());

    uint64_t rip = 0;
    UCK(uc_reg_read(uc_, UC_X86_REG_RIP, &rip), "read RIP");
    if (rip != kReturnAddr)
        throw std::runtime_error(ipt::format("agent stopped at {:#x}", rip));

    uint64_t rax = 0;
    UCK(uc_reg_read(uc_, UC_X86_REG_RAX, &rax), "read RAX");
    return rax;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Scratch helpers
// ═══════════════════════════════════════════════════════════════════════════

uint64_t StoreAgentMachine::Scratch(const void* data, uint64_t len) {
    uint64_t reserved = AlignUp(std::max(len, uint64_t(1)), 16);
    if (scratchCursor_ + reserved > kScratchSize)
        throw std::runtime_error("StoreAgent scratch exhausted");
    uint64_t addr = kScratchBase + scratchCursor_;
    scratchCursor_ += reserved;
    if (data && len) UCK(uc_mem_write(uc_, addr, data, len), "scratch write");
    else if (len) {
        std::vector<uint8_t> z(len, 0);
        UCK(uc_mem_write(uc_, addr, z.data(), len), "scratch zero");
    }
    return addr;
}

void StoreAgentMachine::ClearScratch() {
    if (scratchCursor_) {
        std::vector<uint8_t> z(scratchCursor_, 0);
        uc_mem_write(uc_, kScratchBase, z.data(), scratchCursor_);
    }
    scratchCursor_ = 0;
}

uint64_t StoreAgentMachine::GuestRead64(uint64_t addr) {
    uint64_t v = 0; UCK(uc_mem_read(uc_, addr, &v, 8), "r64"); return v;
}
uint32_t StoreAgentMachine::GuestRead32(uint64_t addr) {
    uint32_t v = 0; UCK(uc_mem_read(uc_, addr, &v, 4), "r32"); return v;
}

// ═══════════════════════════════════════════════════════════════════════════
//  HardwareBlock — same format as SapMachine (24-byte, length-prefixed)
// ═══════════════════════════════════════════════════════════════════════════

/*static*/ std::vector<uint8_t> StoreAgentMachine::HardwareBlock(std::span<const uint8_t> id) {
    if (id.empty() || id.size() > 20)
        throw std::runtime_error("StoreAgent hardware ID must be 1-20 bytes");
    std::vector<uint8_t> block(24, 0);
    uint32_t sz = static_cast<uint32_t>(id.size());
    std::memcpy(block.data(),     &sz,       4);
    std::memcpy(block.data() + 4, id.data(), id.size());
    return block;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SAP Protocol — port of storeagent.go initializeGlobal / initializeSession
// ═══════════════════════════════════════════════════════════════════════════

uint32_t StoreAgentMachine::InitializeGlobal(std::span<const uint8_t> hardwareID) {
    auto hw = HardwareBlock(hardwareID);

    // SC Info path as null-terminated C string
    std::string scPath(kSCInfoPath);
    scPath += '\0';

    uint64_t hwAddr      = Scratch(hw.data(), hw.size());
    uint64_t pathAddr    = Scratch(scPath.data(), scPath.size());
    uint64_t ctxField    = Scratch(4); // uint32 out-param

    // Signature: FairPlayGlobalContextInit(0, hardwareBlock, scInfoPath, &ctx).
    // The leading 0 is a real argument (upstream storeagent.go passes it too);
    // dropping it shifts every argument by one register and the call fails
    // with -42023 (the context out-param never gets written).
    int32_t status = static_cast<int32_t>(
        Invoke(kGlobalInit, { 0ULL, hwAddr, pathAddr, ctxField }));

    uint32_t ctx = GuestRead32(ctxField);
    ClearScratch();

    if (status != 0)
        throw std::runtime_error(ipt::format("StoreAgent GlobalInit returned {}", status));
    if (!ctx)
        throw std::runtime_error("StoreAgent GlobalInit returned null context");
    return ctx;
}

uint64_t StoreAgentMachine::InitializeSession(uint32_t globalCtx,
                                               std::span<const uint8_t> dpInfo) {
    if (dpInfo.empty())
        throw std::runtime_error("StoreAgent dpInfo is empty");

    uint64_t dpAddr     = Scratch(dpInfo.data(), dpInfo.size());
    uint64_t sessField  = Scratch(8); // uint64 out-param

    int32_t status = static_cast<int32_t>(
        Invoke(kSessionInit, {
            uint64_t(globalCtx),
            dpAddr,
            uint64_t(dpInfo.size()),
            sessField
        }));

    uint64_t session = GuestRead64(sessField);
    ClearScratch();

    if (status != 0)
        throw std::runtime_error(ipt::format("StoreAgent SessionInit returned {}", status));
    if (!session)
        throw std::runtime_error("StoreAgent SessionInit returned null session");
    return session;
}

// ═══════════════════════════════════════════════════════════════════════════
//  DecryptChunk — in-place decryption, up to kChunkSize bytes
// ═══════════════════════════════════════════════════════════════════════════

void StoreAgentMachine::DecryptChunk(uint64_t session, std::span<uint8_t> data) {
    if (data.empty()) return;
    if (data.size() > kChunkSize)
        throw std::runtime_error(ipt::format("DecryptChunk: {} > {}", data.size(), kChunkSize));

    uint64_t addr = Scratch(data.data(), data.size());

    int32_t status = static_cast<int32_t>(
        Invoke(kDecryptEntry, {
            session,
            addr,
            uint64_t(data.size()),
            addr,   // output = same buffer (in-place)
            0ULL
        }));

    if (status != 0) {
        ClearScratch();
        throw std::runtime_error(ipt::format("StoreAgent decrypt returned {}", status));
    }

    // Read decrypted bytes back to host
    UCK(uc_mem_read(uc_, addr, data.data(), data.size()), "read decrypted chunk");
    ClearScratch();
}

// ═══════════════════════════════════════════════════════════════════════════
//  CloseSession
// ═══════════════════════════════════════════════════════════════════════════

void StoreAgentMachine::CloseSession(uint64_t session) {
    if (!session) return;
    int32_t st = static_cast<int32_t>(Invoke(kSessionClose, { session }));
    ClearScratch();
    if (st != 0)
        throw std::runtime_error(ipt::format("StoreAgent CloseSession returned {}", st));
}

// ═══════════════════════════════════════════════════════════════════════════
//  ADI — storeagent's CoreADI wrappers
// ═══════════════════════════════════════════════════════════════════════════

void StoreAgentMachine::RequireADI() const {
    if (!adiLoaded_)
        throw std::runtime_error("StoreAgent ADI is unavailable (CoreADI not loaded)");
}

std::vector<uint8_t> StoreAgentMachine::GuestReadBytes(uint64_t addr, uint32_t len) {
    if (!addr || !len) return {};
    if (len > (uint32_t(1) << 24))
        throw std::runtime_error(ipt::format("ADI output too large ({} bytes)", len));
    std::vector<uint8_t> out(len);
    UCK(uc_mem_read(uc_, addr, out.data(), len), "read ADI output");
    return out;
}

StoreAgentMachine::AdiStartResult
StoreAgentMachine::AdiStartProvisioning(uint64_t dsid, std::span<const uint8_t> serverData) {
    RequireADI();
    if (serverData.empty())
        throw std::runtime_error("ADI provisioning data (x-apple-md-data) is empty");

    uint64_t inAddr  = Scratch(serverData.data(), serverData.size());
    uint64_t ptrFld  = Scratch(8);
    uint64_t lenFld  = Scratch(4);
    uint64_t sessFld = Scratch(4);

    int32_t status = static_cast<int32_t>(Invoke(kAdiStart, {
        dsid, inAddr, uint64_t(serverData.size()), ptrFld, lenFld, sessFld }));

    AdiStartResult r;
    if (status == 0) {
        r.clientData = GuestReadBytes(GuestRead64(ptrFld), GuestRead32(lenFld));
        r.session    = GuestRead32(sessFld);
    }
    ClearScratch();

    if (status != 0)
        throw std::runtime_error(ipt::format("ADI start provisioning returned {}", status));
    if (r.clientData.empty())
        throw std::runtime_error("ADI start provisioning returned no client data");
    return r;
}

void StoreAgentMachine::AdiEndProvisioning(uint32_t session,
                                           std::span<const uint8_t> settingInfo,
                                           std::span<const uint8_t> transportKey) {
    RequireADI();
    if (settingInfo.empty() || transportKey.empty())
        throw std::runtime_error("ADI end provisioning: settingInfo/transportKey is empty");

    uint64_t siAddr = Scratch(settingInfo.data(),  settingInfo.size());
    uint64_t tkAddr = Scratch(transportKey.data(), transportKey.size());

    int32_t status = static_cast<int32_t>(Invoke(kAdiEnd, {
        uint64_t(session),
        siAddr, uint64_t(settingInfo.size()),
        tkAddr, uint64_t(transportKey.size()) }));
    ClearScratch();

    if (status != 0)
        throw std::runtime_error(ipt::format("ADI end provisioning returned {}", status));
}

std::optional<StoreAgentMachine::AdiOTP>
StoreAgentMachine::AdiRequestOTP(uint64_t dsid, int32_t* statusOut) {
    RequireADI();
    uint64_t midPtr = Scratch(8);
    uint64_t midLen = Scratch(4);
    uint64_t otpPtr = Scratch(8);
    uint64_t otpLen = Scratch(4);

    int32_t status = static_cast<int32_t>(Invoke(kAdiOTP, {
        dsid, midPtr, midLen, otpPtr, otpLen }));
    if (statusOut) *statusOut = status;

    std::optional<AdiOTP> r;
    if (status == 0) {
        AdiOTP o;
        o.machineID = GuestReadBytes(GuestRead64(midPtr), GuestRead32(midLen));
        o.otp       = GuestReadBytes(GuestRead64(otpPtr), GuestRead32(otpLen));
        if (!o.machineID.empty() && !o.otp.empty()) r = std::move(o);
    }
    ClearScratch();
    return r;
}

int32_t StoreAgentMachine::AdiErase(uint64_t dsid) {
    RequireADI();
    int32_t status = static_cast<int32_t>(Invoke(kAdiErase, { dsid }));
    ClearScratch();
    return status;
}

StoreAgentMachine::AdiSyncResult
StoreAgentMachine::AdiSynchronize(uint64_t dsid, std::span<const uint8_t> serverData) {
    RequireADI();
    if (serverData.empty())
        throw std::runtime_error("ADI machine sync data (x-apple-md-data) is empty");

    // Output order: machine ID first, then the sync message that storeagent
    // posts as "clientData" (-[ADIMachineSyncOperation run]: r15 → machineId,
    // r12 → clientData).
    uint64_t inAddr = Scratch(serverData.data(), serverData.size());
    uint64_t midPtr = Scratch(8);
    uint64_t midLen = Scratch(4);
    uint64_t cdPtr  = Scratch(8);
    uint64_t cdLen  = Scratch(4);

    int32_t status = static_cast<int32_t>(Invoke(kAdiSync, {
        dsid, inAddr, uint64_t(serverData.size()), midPtr, midLen, cdPtr, cdLen }));

    AdiSyncResult r;
    if (status == 0) {
        r.machineId  = GuestReadBytes(GuestRead64(midPtr), GuestRead32(midLen));
        r.clientData = GuestReadBytes(GuestRead64(cdPtr),  GuestRead32(cdLen));
    }
    ClearScratch();

    if (status != 0)
        throw std::runtime_error(ipt::format("ADI machine sync returned {}", status));
    if (r.clientData.empty())
        throw std::runtime_error("ADI machine sync returned no client data");
    return r;
}

std::vector<uint8_t> StoreAgentMachine::GetSyncState() const {
    const auto& files = shims_->GetVirtualFiles();
    auto it = files.find(kSyncStatePath);
    return it != files.end() ? it->second : std::vector<uint8_t>{};
}

void StoreAgentMachine::SetSyncState(std::vector<uint8_t> state) {
    auto files = shims_->GetVirtualFiles();
    if (state.empty()) files.erase(kSyncStatePath);
    else               files[kSyncStatePath] = std::move(state);
    shims_->SetVirtualFiles(std::move(files), shims_->GetVirtualDirs());
}

int32_t StoreAgentMachine::ImportKeyBag(uint32_t globalCtx, std::span<const uint8_t> keyBag) {
    if (keyBag.empty()) throw std::runtime_error("FairPlay keybag is empty");
    uint64_t kbAddr = Scratch(keyBag.data(), keyBag.size());
    int32_t status = static_cast<int32_t>(Invoke(kImportKeyBag, {
        uint64_t(globalCtx), kbAddr, uint64_t(keyBag.size()) }));
    ClearScratch();
    return status;
}

// ─── ADI state (de)serialisation ─────────────────────────────────────────────
//  "ADIS" | u32 version=1 | uuid[16] | u32 nFiles | {u32 len, path, u32 len, data}…
//         | u32 nDirs | {u32 len, path}…        (little-endian)

static constexpr uint32_t kAdiStateMagic   = 0x53494441; // "ADIS"
static constexpr uint32_t kAdiStateVersion = 1;

std::vector<uint8_t> StoreAgentMachine::ExportAdiState() const {
    RequireADI();
    std::vector<uint8_t> out;
    auto put32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    auto putBytes = [&](const void* p, size_t n) {
        put32(static_cast<uint32_t>(n));
        auto b = static_cast<const uint8_t*>(p);
        out.insert(out.end(), b, b + n);
    };
    put32(kAdiStateMagic);
    put32(kAdiStateVersion);
    out.insert(out.end(), hostUUID_.begin(), hostUUID_.end());
    const auto& files = shims_->GetVirtualFiles();
    put32(static_cast<uint32_t>(files.size()));
    for (const auto& [path, data] : files) {
        putBytes(path.data(), path.size());
        putBytes(data.data(), data.size());
    }
    const auto& dirs = shims_->GetVirtualDirs();
    put32(static_cast<uint32_t>(dirs.size()));
    for (const auto& d : dirs) putBytes(d.data(), d.size());
    return out;
}

void StoreAgentMachine::ImportAdiState(std::span<const uint8_t> state) {
    RequireADI();
    size_t pos = 0;
    auto need = [&](size_t n) {
        if (state.size() - pos < n) throw std::runtime_error("ADI state is truncated");
    };
    auto get32 = [&]() {
        need(4);
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= uint32_t(state[pos + i]) << (8 * i);
        pos += 4;
        return v;
    };
    auto getBytes = [&]() {
        uint32_t n = get32();
        need(n);
        std::vector<uint8_t> v(state.begin() + pos, state.begin() + pos + n);
        pos += n;
        return v;
    };

    if (get32() != kAdiStateMagic)   throw std::runtime_error("ADI state: bad magic");
    if (get32() != kAdiStateVersion) throw std::runtime_error("ADI state: unsupported version");
    need(16);
    std::array<uint8_t, 16> uuid{};
    std::memcpy(uuid.data(), state.data() + pos, 16);
    pos += 16;

    SapShims::VirtualFiles files;
    for (uint32_t i = 0, n = get32(); i < n; ++i) {
        auto p = getBytes();
        files[std::string(p.begin(), p.end())] = getBytes();
    }
    std::set<std::string> dirs;
    for (uint32_t i = 0, n = get32(); i < n; ++i) {
        auto p = getBytes();
        dirs.insert(std::string(p.begin(), p.end()));
    }

    hostUUID_ = uuid;
    shims_->SetHostUUID(uuid);
    shims_->SetVirtualFiles(std::move(files), std::move(dirs));
}

// ═══════════════════════════════════════════════════════════════════════════
//  KBSyncData — FairPlayKBSyncDataWithDSID (port of sapsigner emulator)
// ═══════════════════════════════════════════════════════════════════════════

std::vector<uint8_t> StoreAgentMachine::KBSyncData(uint32_t globalCtx, uint64_t dsid) {
    uint64_t ptrFld = Scratch(8);   // out: pointer to the blob
    uint64_t lenFld = Scratch(8);   // out: uint32 length (zeroed 8 bytes)

    int32_t status = static_cast<int32_t>(
        Invoke(kKBSyncData, { uint64_t(globalCtx), dsid, 0ULL, 1ULL, ptrFld, lenFld }));

    uint64_t ptr = GuestRead64(ptrFld);
    uint32_t len = GuestRead32(lenFld);
    ClearScratch();

    if (status != 0)
        throw std::runtime_error(ipt::format("FairPlayKBSyncDataWithDSID returned {}", status));
    if (!ptr || !len)
        throw std::runtime_error("FairPlayKBSyncDataWithDSID returned an empty buffer");

    std::vector<uint8_t> out(len);
    UCK(uc_mem_read(uc_, ptr, out.data(), len), "read kbsync");

    if (disposeFn_) {
        try { Invoke(disposeFn_, { ptr }); } catch (...) {} // non-fatal
    }
    return out;
}
