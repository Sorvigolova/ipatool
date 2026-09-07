#include "StoreAgentMachine.h"
#include "SapMachine.h"

#include <unicorn/unicorn.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include "compat_format.h"
#include <stdexcept>

// x86-64 SysV arg registers — same as SapMachine
static constexpr int kArgRegs[6] = {
    UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
    UC_X86_REG_RCX, UC_X86_REG_R8,  UC_X86_REG_R9,
};
static constexpr uint64_t kTimeoutUs = 60'000'000ULL;

static inline void UCK(uc_err e, const char* w) {
    if (e != UC_ERR_OK)
        throw std::runtime_error(std::format("{}: {}", w, uc_strerror(e)));
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
    std::vector<uint8_t> storeAgent)
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

    // 8. Load into Unicorn
    imgCoreFP      ->Load(m->uc_);
    imgCommerceCore->Load(m->uc_);
    imgCommerceKit ->Load(m->uc_);
    imgAgent       ->Load(m->uc_);

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

    uint64_t rsp = kStackEnd - 8;
    if (rsp % 16 != 8) rsp -= 8;
    UCK(uc_mem_write(uc_, rsp, &kReturnAddr, 8), "push return addr");
    UCK(uc_reg_write(uc_, UC_X86_REG_RSP, &rsp), "write RSP");

    uc_err err = uc_emu_start(uc_, fn, kReturnAddr, kTimeoutUs, 0);
    if (err != UC_ERR_OK && !shims_->HasFault())
        throw std::runtime_error(std::format("uc_emu_start: {}", uc_strerror(err)));
    if (shims_->HasFault())
        throw std::runtime_error(shims_->TakeFault());

    uint64_t rip = 0;
    UCK(uc_reg_read(uc_, UC_X86_REG_RIP, &rip), "read RIP");
    if (rip != kReturnAddr)
        throw std::runtime_error(std::format("agent stopped at {:#x}", rip));

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

    int32_t status = static_cast<int32_t>(
        Invoke(kGlobalInit, { hwAddr, pathAddr, ctxField }));

    uint32_t ctx = GuestRead32(ctxField);
    ClearScratch();

    if (status != 0)
        throw std::runtime_error(std::format("StoreAgent GlobalInit returned {}", status));
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
        throw std::runtime_error(std::format("StoreAgent SessionInit returned {}", status));
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
        throw std::runtime_error(std::format("DecryptChunk: {} > {}", data.size(), kChunkSize));

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
        throw std::runtime_error(std::format("StoreAgent decrypt returned {}", status));
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
        throw std::runtime_error(std::format("StoreAgent CloseSession returned {}", st));
}
