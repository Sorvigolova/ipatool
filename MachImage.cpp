#include "MachImage.h"

#include <unicorn/unicorn.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include "compat_format.h"
#include <span>
#include <stdexcept>

// ─── Mach-O type definitions (Windows-portable, all little-endian) ────────────

// Fat (universal) binary — header is big-endian
static constexpr uint32_t FAT_MAGIC    = 0xCAFEBABE;
static constexpr uint32_t FAT_CIGAM    = 0xBEBAFECA;  // swapped on LE host
static constexpr uint32_t MH_MAGIC_64  = 0xFEEDFACF;
static constexpr uint32_t CPU_TYPE_X86_64 = 0x01000007;

#pragma pack(push, 1)

struct fat_header { uint32_t magic; uint32_t nfat_arch; };
struct fat_arch   {
    uint32_t cputype; uint32_t cpusubtype;
    uint32_t offset;  uint32_t size; uint32_t align;
};

struct mach_header_64 {
    uint32_t magic, cputype, cpusubtype, filetype;
    uint32_t ncmds, sizeofcmds, flags;
    uint32_t reserved;
};

struct load_command { uint32_t cmd, cmdsize; };

struct segment_command_64 {
    uint32_t cmd, cmdsize;
    char     segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t maxprot, initprot, nsects, flags;
};

struct dyld_info_command {
    uint32_t cmd, cmdsize;
    uint32_t rebase_off,  rebase_size;
    uint32_t bind_off,    bind_size;
    uint32_t weak_bind_off, weak_bind_size;
    uint32_t lazy_bind_off, lazy_bind_size;
    uint32_t export_off,  export_size;
};

struct symtab_command {
    uint32_t cmd, cmdsize;
    uint32_t symoff, nsyms, stroff, strsize;
};

struct nlist_64 {
    uint32_t n_strx;
    uint8_t  n_type, n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

// LC_DYLD_EXPORTS_TRIE (0x80000033)
struct linkedit_data_command {
    uint32_t cmd, cmdsize;
    uint32_t dataoff, datasize;
};

#pragma pack(pop)

static constexpr uint32_t LC_SEGMENT_64          = 0x19;
static constexpr uint32_t LC_SYMTAB              = 0x02;
static constexpr uint32_t LC_DYLD_INFO           = 0x22;
static constexpr uint32_t LC_DYLD_INFO_ONLY      = 0x22 | 0x80000000u;
static constexpr uint32_t LC_DYLD_EXPORTS_TRIE   = 0x80000033u;

// N_TYPE mask / values
static constexpr uint8_t  N_TYPE  = 0x0E;
static constexpr uint8_t  N_SECT  = 0x0E;
static constexpr uint8_t  N_EXT   = 0x01;

// Rebase opcodes
static constexpr uint8_t REBASE_OPCODE_MASK                           = 0xF0;
static constexpr uint8_t REBASE_IMM_MASK                              = 0x0F;
static constexpr uint8_t REBASE_OPCODE_DONE                           = 0x00;
static constexpr uint8_t REBASE_OPCODE_SET_TYPE_IMM                   = 0x10;
static constexpr uint8_t REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB    = 0x20;
static constexpr uint8_t REBASE_OPCODE_ADD_ADDR_ULEB                  = 0x30;
static constexpr uint8_t REBASE_OPCODE_ADD_ADDR_IMM_SCALED            = 0x40;
static constexpr uint8_t REBASE_OPCODE_DO_REBASE_IMM_TIMES            = 0x50;
static constexpr uint8_t REBASE_OPCODE_DO_REBASE_ULEB_TIMES           = 0x60;
static constexpr uint8_t REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB        = 0x70;
static constexpr uint8_t REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIP_ULEB = 0x80;

// Bind opcodes
static constexpr uint8_t BIND_OPCODE_MASK                             = 0xF0;
static constexpr uint8_t BIND_IMM_MASK                                = 0x0F;
static constexpr uint8_t BIND_OPCODE_DONE                             = 0x00;
static constexpr uint8_t BIND_OPCODE_SET_DYLIB_ORDINAL_IMM            = 0x10;
static constexpr uint8_t BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB           = 0x20;
static constexpr uint8_t BIND_OPCODE_SET_DYLIB_SPECIAL_IMM            = 0x30;
static constexpr uint8_t BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM    = 0x40;
static constexpr uint8_t BIND_OPCODE_SET_TYPE_IMM                     = 0x50;
static constexpr uint8_t BIND_OPCODE_SET_ADDEND_SLEB                  = 0x60;
static constexpr uint8_t BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB      = 0x70;
static constexpr uint8_t BIND_OPCODE_ADD_ADDR_ULEB                    = 0x80;
static constexpr uint8_t BIND_OPCODE_DO_BIND                          = 0x90;
static constexpr uint8_t BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB            = 0xA0;
static constexpr uint8_t BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED      = 0xB0;
static constexpr uint8_t BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIP_ULEB     = 0xC0;

static constexpr uint64_t POINTER_SIZE  = 8;
static constexpr uint64_t PAGE_SIZE     = 0x1000;
// MAX_IMG_SPAN removed (unused)

// ─── helpers ─────────────────────────────────────────────────────────────────

static inline uint32_t bswap32(uint32_t v) {
    return ((v & 0xFF000000u) >> 24) | ((v & 0x00FF0000u) >> 8)
         | ((v & 0x0000FF00u) <<  8) | ((v & 0x000000FFu) << 24);
}

static uint64_t ReadULEB128(const uint8_t*& p, const uint8_t* end) {
    uint64_t value = 0; int shift = 0;
    while (p < end) {
        uint8_t b = *p++;
        value |= uint64_t(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
        if (shift >= 64) throw std::runtime_error("ULEB128 overflow");
    }
    return value;
}

static int64_t ReadSLEB128(const uint8_t*& p, const uint8_t* end) {
    int64_t value = 0; int shift = 0;
    uint8_t b = 0;
    while (p < end) {
        b = *p++;
        value |= int64_t(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
        if (shift >= 64) throw std::runtime_error("SLEB128 overflow");
    }
    if (shift < 64 && (b & 0x40))
        value |= -(int64_t(1) << shift);
    return value;
}

static inline uint64_t AlignUp(uint64_t v, uint64_t a) {
    return (v + a - 1) & ~(a - 1);
}

// ─── Open ─────────────────────────────────────────────────────────────────────

std::unique_ptr<MachImage> MachImage::Open(std::string name, std::vector<uint8_t> data) {
    if (data.size() < 4)
        throw std::runtime_error(std::format("MachImage::Open({}): file too small", name));

    auto img = std::unique_ptr<MachImage>(new MachImage());
    img->name_ = std::move(name);

    // Fat binary? (big-endian magic)
    uint32_t magic;
    std::memcpy(&magic, data.data(), 4);
    if (magic == FAT_MAGIC || magic == FAT_CIGAM)
        img->data_ = ExtractAmd64Slice(data);
    else
        img->data_ = std::move(data);

    img->ParseLoadCommands();
    return img;
}

// ─── ExtractAmd64Slice ────────────────────────────────────────────────────────

std::vector<uint8_t> MachImage::ExtractAmd64Slice(const std::vector<uint8_t>& fat) {
    if (fat.size() < sizeof(fat_header))
        throw std::runtime_error("Fat binary: too small for header");

    fat_header hdr;
    std::memcpy(&hdr, fat.data(), sizeof(hdr));
    // Fat header is big-endian
    uint32_t narch = bswap32(hdr.nfat_arch);

    const uint8_t* p = fat.data() + sizeof(fat_header);
    for (uint32_t i = 0; i < narch; ++i) {
        if (p + sizeof(fat_arch) > fat.data() + fat.size())
            throw std::runtime_error("Fat binary: arch table truncated");
        fat_arch arch;
        std::memcpy(&arch, p, sizeof(arch));
        p += sizeof(fat_arch);

        uint32_t cpu    = bswap32(arch.cputype);
        uint32_t offset = bswap32(arch.offset);
        uint32_t size   = bswap32(arch.size);

        if (cpu != CPU_TYPE_X86_64) continue;

        if (uint64_t(offset) + size > fat.size())
            throw std::runtime_error("Fat binary: x86-64 slice out of bounds");

        return std::vector<uint8_t>(fat.data() + offset,
                                    fat.data() + offset + size);
    }
    throw std::runtime_error("Fat binary has no x86-64 slice");
}

// ─── ParseLoadCommands ────────────────────────────────────────────────────────

void MachImage::ParseLoadCommands() {
    const uint8_t* base = data_.data();
    size_t total        = data_.size();

    if (total < sizeof(mach_header_64))
        throw std::runtime_error(std::format("{}: too small", name_));

    mach_header_64 mh;
    std::memcpy(&mh, base, sizeof(mh));

    if (mh.magic != MH_MAGIC_64)
        throw std::runtime_error(std::format("{}: not a 64-bit Mach-O (magic={:#x})", name_, mh.magic));
    if ((mh.cputype & 0x00FFFFFFu) != (CPU_TYPE_X86_64 & 0x00FFFFFFu))
        throw std::runtime_error(std::format("{}: not x86-64", name_));

    const uint8_t* lc_ptr = base + sizeof(mach_header_64);
    const uint8_t* lc_end = lc_ptr + mh.sizeofcmds;
    if (lc_end > base + total)
        throw std::runtime_error(std::format("{}: load commands extend past file", name_));

    // Pointers to deferred sections (export trie, dyld info, symtab)
    const uint8_t* rebaseOpcodes    = nullptr; uint32_t rebaseSize    = 0;
    const uint8_t* bindOpcodes      = nullptr; uint32_t bindSize      = 0;
    const uint8_t* lazyBindOpcodes  = nullptr; uint32_t lazyBindSize  = 0;
    const uint8_t* exportTrie       = nullptr; uint32_t exportTrieSize = 0;
    const uint8_t* symtabSyms       = nullptr; uint32_t symtabNsyms   = 0;
    const char*    symtabStrtab     = nullptr; uint32_t symtabStrsize  = 0;

    bool firstText = true;

    while (lc_ptr < lc_end) {
        load_command lc;
        std::memcpy(&lc, lc_ptr, sizeof(lc));

        if (lc.cmdsize < sizeof(load_command) || lc_ptr + lc.cmdsize > lc_end)
            throw std::runtime_error(std::format("{}: malformed load command", name_));

        if (lc.cmd == LC_SEGMENT_64) {
            segment_command_64 sc;
            std::memcpy(&sc, lc_ptr, sizeof(sc));

            Segment seg;
            seg.name.assign(sc.segname, strnlen(sc.segname, 16));
            seg.vmAddr   = sc.vmaddr;
            seg.vmSize   = sc.vmsize;
            seg.fileOff  = sc.fileoff;
            seg.fileSize = sc.filesize;

            // Validate
            if (seg.fileSize > seg.vmSize)
                throw std::runtime_error(std::format("{}: segment {} file > mem", name_, seg.name));
            if (seg.fileOff + seg.fileSize > total)
                throw std::runtime_error(std::format("{}: segment {} beyond EOF", name_, seg.name));

            // Image base = vmaddr of first non-__PAGEZERO segment
            if (firstText && seg.name != "__PAGEZERO") {
                imageBase_ = seg.vmAddr;
                firstText  = false;
            }

            segments_.push_back(std::move(seg));
        }
        else if (lc.cmd == LC_DYLD_INFO || lc.cmd == LC_DYLD_INFO_ONLY) {
            dyld_info_command di;
            std::memcpy(&di, lc_ptr, sizeof(di));

            auto SafePtr = [&](uint32_t off, uint32_t sz) -> const uint8_t* {
                if (sz == 0) return nullptr;
                if (uint64_t(off) + sz > total)
                    throw std::runtime_error(std::format("{}: dyld_info out of bounds", name_));
                return base + off;
            };

            rebaseOpcodes   = SafePtr(di.rebase_off, di.rebase_size);
            rebaseSize      = di.rebase_size;
            bindOpcodes     = SafePtr(di.bind_off, di.bind_size);
            bindSize        = di.bind_size;
            lazyBindOpcodes = SafePtr(di.lazy_bind_off, di.lazy_bind_size);
            lazyBindSize    = di.lazy_bind_size;
            exportTrie      = SafePtr(di.export_off, di.export_size);
            exportTrieSize  = di.export_size;
        }
        else if (lc.cmd == LC_DYLD_EXPORTS_TRIE) {
            linkedit_data_command led;
            std::memcpy(&led, lc_ptr, sizeof(led));
            if (led.datasize > 0 && uint64_t(led.dataoff) + led.datasize <= total) {
                exportTrie     = base + led.dataoff;
                exportTrieSize = led.datasize;
            }
        }
        else if (lc.cmd == LC_SYMTAB) {
            symtab_command sc;
            std::memcpy(&sc, lc_ptr, sizeof(sc));
            if (sc.nsyms > 0 && uint64_t(sc.symoff) + sc.nsyms * sizeof(nlist_64) <= total) {
                symtabSyms   = base + sc.symoff;
                symtabNsyms  = sc.nsyms;
            }
            if (sc.strsize > 0 && uint64_t(sc.stroff) + sc.strsize <= total) {
                symtabStrtab  = reinterpret_cast<const char*>(base + sc.stroff);
                symtabStrsize = sc.strsize;
            }
        }

        lc_ptr += lc.cmdsize;
    }

    // Parse deferred sections
    if (rebaseOpcodes) ParseRebaseOpcodes(rebaseOpcodes, rebaseSize);
    if (bindOpcodes)   ParseBindOpcodes(bindOpcodes,   bindSize,  /*isLazy=*/false);
    if (lazyBindOpcodes) ParseBindOpcodes(lazyBindOpcodes, lazyBindSize, /*isLazy=*/true);
    if (exportTrie)    ParseExportTrie(exportTrie, exportTrieSize);
    if (symtabSyms && symtabStrtab)
        ParseSymtab(symtabSyms, symtabNsyms, symtabStrtab, symtabStrsize);
}

// ─── ParseRebaseOpcodes ───────────────────────────────────────────────────────

void MachImage::ParseRebaseOpcodes(const uint8_t* start, size_t len) {
    const uint8_t* p   = start;
    const uint8_t* end = start + len;

    uint8_t  type    = 0;
    int      segIdx  = -1;
    uint64_t offset  = 0;

    auto CurrentSegName = [&]() -> const std::string& {
        if (segIdx < 0 || segIdx >= static_cast<int>(segments_.size()))
            throw std::runtime_error(std::format("{}: rebase: invalid segment index {}", name_, segIdx));
        return segments_[segIdx].name;
    };

    auto EmitRebase = [&]() {
        if (type != 1 /*REBASE_TYPE_POINTER*/)
            throw std::runtime_error(std::format("{}: unsupported rebase type {}", name_, type));
        // Read original pointer value from data[]
        uint64_t fileOff = SegmentFileOffset(CurrentSegName(), offset, POINTER_SIZE);
        uint64_t origVal = ReadPointer(fileOff);
        rebases_.push_back({ CurrentSegName(), offset, origVal });
    };

    while (p < end) {
        uint8_t b      = *p++;
        uint8_t opcode = b & REBASE_OPCODE_MASK;
        uint8_t imm    = b & REBASE_IMM_MASK;

        switch (opcode) {
        case REBASE_OPCODE_DONE:
            return;
        case REBASE_OPCODE_SET_TYPE_IMM:
            type = imm;
            break;
        case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            segIdx = imm;
            offset = ReadULEB128(p, end);
            break;
        case REBASE_OPCODE_ADD_ADDR_ULEB:
            offset += ReadULEB128(p, end);
            break;
        case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            offset += imm * POINTER_SIZE;
            break;
        case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
            for (uint8_t i = 0; i < imm; ++i) { EmitRebase(); offset += POINTER_SIZE; }
            break;
        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
            uint64_t count = ReadULEB128(p, end);
            for (uint64_t i = 0; i < count; ++i) { EmitRebase(); offset += POINTER_SIZE; }
            break;
        }
        case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
            EmitRebase();
            offset += POINTER_SIZE + ReadULEB128(p, end);
            break;
        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIP_ULEB: {
            uint64_t count = ReadULEB128(p, end);
            uint64_t skip  = ReadULEB128(p, end);
            for (uint64_t i = 0; i < count; ++i) { EmitRebase(); offset += POINTER_SIZE + skip; }
            break;
        }
        default:
            throw std::runtime_error(std::format("{}: unknown rebase opcode {:#x}", name_, opcode));
        }
    }
}

// ─── ParseBindOpcodes ─────────────────────────────────────────────────────────

void MachImage::ParseBindOpcodes(const uint8_t* start, size_t len, bool isLazy) {
    const uint8_t* p   = start;
    const uint8_t* end = start + len;

    int         segIdx  = -1;
    uint64_t    offset  = 0;
    std::string symName;
    int64_t     addend  = 0;
    // type/ordinal are tracked but not stored (we only support pointer binds)

    auto CurrentSegName = [&]() -> const std::string& {
        if (segIdx < 0 || segIdx >= static_cast<int>(segments_.size()))
            throw std::runtime_error(std::format("{}: bind: invalid segment {}", name_, segIdx));
        return segments_[segIdx].name;
    };

    auto EmitBind = [&]() {
        if (symName.empty())
            throw std::runtime_error(std::format("{}: bind: empty symbol name", name_));
        binds_.push_back({ CurrentSegName(), offset, symName, addend });
    };

    while (p < end) {
        uint8_t b      = *p++;
        uint8_t opcode = b & BIND_OPCODE_MASK;
        uint8_t imm    = b & BIND_IMM_MASK;

        switch (opcode) {
        case BIND_OPCODE_DONE:
            if (!isLazy) return;
            // Lazy bind: DONE ends one symbol's record, stream continues.
            // Reset per-record state so the next entry starts clean.
            segIdx  = -1;
            offset  = 0;
            symName.clear();
            addend  = 0;
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            // We don't validate the library ordinal — all symbols route through resolve()
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            ReadULEB128(p, end); // consume, ignore
            break;
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
            // NUL-terminated symbol name follows
            const char* s = reinterpret_cast<const char*>(p);
            symName.assign(s);
            p += symName.size() + 1;
            break;
        }
        case BIND_OPCODE_SET_TYPE_IMM:
            // imm == 1 (pointer) — only type we support; others would throw in Relocate
            break;
        case BIND_OPCODE_SET_ADDEND_SLEB:
            addend = ReadSLEB128(p, end);
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            segIdx = imm;
            offset = ReadULEB128(p, end);
            break;
        case BIND_OPCODE_ADD_ADDR_ULEB:
            offset += ReadULEB128(p, end);
            break;
        case BIND_OPCODE_DO_BIND:
            EmitBind(); offset += POINTER_SIZE;
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            EmitBind(); offset += POINTER_SIZE + ReadULEB128(p, end);
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            EmitBind(); offset += POINTER_SIZE + imm * POINTER_SIZE;
            break;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIP_ULEB: {
            uint64_t count = ReadULEB128(p, end);
            uint64_t skip  = ReadULEB128(p, end);
            for (uint64_t i = 0; i < count; ++i) { EmitBind(); offset += POINTER_SIZE + skip; }
            break;
        }
        default:
            throw std::runtime_error(std::format("{}: unknown bind opcode {:#x}", name_, opcode));
        }
    }
}

// ─── ParseExportTrie ─────────────────────────────────────────────────────────

void MachImage::ParseExportTrie(const uint8_t* trie, size_t len) {
    std::string prefix;
    WalkTrie(trie, len, 0, prefix);
}

void MachImage::WalkTrie(const uint8_t* trie, size_t len,
                          size_t nodeOff, std::string& prefix) {
    if (nodeOff >= len) return;

    const uint8_t* p   = trie + nodeOff;
    const uint8_t* end = trie + len;

    // Terminal size ULEB128
    uint64_t termSize = ReadULEB128(p, end);
    if (termSize != 0) {
        // Exported: read flags and address
        const uint8_t* tp  = p;
        const uint8_t* te  = p + termSize;
        uint64_t flags     = ReadULEB128(tp, te);
        (void)flags;
        uint64_t addr      = ReadULEB128(tp, te);
        // addr is relative to image base (in-image vmAddr)
        exports_[prefix]   = imageBase_ + addr;
    }

    p += termSize;
    if (p >= end) return;

    uint8_t childCount = *p++;
    for (uint8_t i = 0; i < childCount; ++i) {
        // Edge label: NUL-terminated string
        const char* label = reinterpret_cast<const char*>(p);
        size_t labLen = strnlen(label, end - p);
        p += labLen + 1;

        // Child node offset ULEB128
        uint64_t childOff = ReadULEB128(p, end);

        // Recurse
        size_t prevLen = prefix.size();
        prefix.append(label, labLen);
        WalkTrie(trie, len, static_cast<size_t>(childOff), prefix);
        prefix.resize(prevLen);
    }
}

// ─── ParseSymtab (fallback) ──────────────────────────────────────────────────

void MachImage::ParseSymtab(const uint8_t* syms, uint32_t nsyms,
                              const char* strtab, uint32_t strsize) {
    for (uint32_t i = 0; i < nsyms; ++i) {
        nlist_64 nl;
        std::memcpy(&nl, syms + i * sizeof(nlist_64), sizeof(nl));

        // Skip stabs, undefined, and non-external
        if ((nl.n_type & N_TYPE) != N_SECT) continue;
        if (!(nl.n_type & N_EXT)) continue;
        if (nl.n_value == 0) continue;
        if (nl.n_strx == 0 || nl.n_strx >= strsize) continue;

        std::string sym(strtab + nl.n_strx);
        if (exports_.count(sym) == 0)          // trie wins if both present
            exports_[std::move(sym)] = nl.n_value;
    }
}

// ─── Export ──────────────────────────────────────────────────────────────────

uint64_t MachImage::Export(std::string_view symbol, uint64_t loadBase) const {
    auto it = exports_.find(std::string(symbol));
    if (it == exports_.end())
        throw std::runtime_error(std::format("{}: symbol not found: {}", name_, symbol));

    uint64_t vmAddr = it->second;
    if (vmAddr < imageBase_)
        throw std::runtime_error(std::format("{}: symbol {} precedes image base", name_, symbol));

    return loadBase + (vmAddr - imageBase_);
}

// ─── Relocate ────────────────────────────────────────────────────────────────

void MachImage::Relocate(uint64_t loadBase,
                          std::function<uint64_t(std::string_view)> resolve) {
    if (relocated_)
        throw std::runtime_error(std::format("{}: already relocated", name_));

    // Apply rebases: pointer value is currently in-image vmAddr, slide it.
    for (const auto& r : rebases_) {
        if (r.origValue < imageBase_)
            throw std::runtime_error(std::format("{}: rebase value below image base", name_));

        uint64_t newAddr = loadBase + (r.origValue - imageBase_);
        uint64_t fileOff = SegmentFileOffset(r.segment, r.offset, POINTER_SIZE);
        PutPointer(fileOff, newAddr);
    }

    // Apply binds: resolve external symbol, apply addend, write pointer.
    for (const auto& b : binds_) {
        uint64_t symAddr = resolve(b.symbolName);

        // Apply signed addend
        uint64_t finalAddr;
        if (b.addend >= 0) {
            finalAddr = symAddr + static_cast<uint64_t>(b.addend);
        } else {
            uint64_t mag = static_cast<uint64_t>(-(b.addend + 1)) + 1;
            if (mag > symAddr)
                throw std::runtime_error(std::format("{}: bind addend underflow for {}", name_, b.symbolName));
            finalAddr = symAddr - mag;
        }

        uint64_t fileOff = SegmentFileOffset(b.segment, b.segOffset, POINTER_SIZE);
        PutPointer(fileOff, finalAddr);
    }

    relocated_   = true;
    loadedBase_  = loadBase;
}

// ─── Load ─────────────────────────────────────────────────────────────────────

void MachImage::Load(uc_engine* uc) const {
    if (!relocated_)
        throw std::runtime_error(std::format("{}: must be relocated before Load()", name_));

    // Calculate span: max (vmAddr + vmSize - imageBase) over all loadable segments.
    uint64_t span = 0;
    for (const auto& s : segments_) {
        if (s.name == "__PAGEZERO" || s.vmSize == 0) continue;
        if (s.vmAddr < imageBase_)
            throw std::runtime_error(std::format("{}: segment {} below image base", name_, s.name));
        span = std::max(span, s.vmAddr - imageBase_ + s.vmSize);
    }
    span = AlignUp(span, PAGE_SIZE);
    if (span == 0)
        throw std::runtime_error(std::format("{}: no loadable segments", name_));

    uc_err err = uc_mem_map(uc, loadedBase_, span, UC_PROT_ALL);
    if (err != UC_ERR_OK)
        throw std::runtime_error(std::format("{}: uc_mem_map failed: {}", name_, uc_strerror(err)));

    for (const auto& s : segments_) {
        if (s.name == "__PAGEZERO" || s.fileSize == 0) continue;

        uint64_t guestAddr = loadedBase_ + (s.vmAddr - imageBase_);
        err = uc_mem_write(uc, guestAddr,
                           data_.data() + s.fileOff, s.fileSize);
        if (err != UC_ERR_OK)
            throw std::runtime_error(std::format("{}: uc_mem_write segment {} failed: {}",
                                                  name_, s.name, uc_strerror(err)));
    }
}

// ─── Private helpers ──────────────────────────────────────────────────────────

uint64_t MachImage::SegmentFileOffset(std::string_view segName,
                                       uint64_t offset, uint64_t size) const {
    for (const auto& s : segments_) {
        if (s.name != segName) continue;

        if (offset + size > s.vmSize)
            throw std::runtime_error(std::format("{}: fixup at {:#x} exceeds segment {}",
                                                  name_, offset, segName));
        if (offset + size > s.fileSize)
            throw std::runtime_error(std::format("{}: fixup at {:#x} past file data in {}",
                                                  name_, offset, segName));

        uint64_t result = s.fileOff + offset;
        if (result + size > data_.size())
            throw std::runtime_error(std::format("{}: fixup at {:#x} beyond EOF", name_, result));

        return result;
    }
    throw std::runtime_error(std::format("{}: fixup references unknown segment {}", name_, segName));
}

void MachImage::PutPointer(uint64_t fileOffset, uint64_t value) {
    if (fileOffset + 8 > data_.size())
        throw std::runtime_error(std::format("{}: PutPointer at {:#x} beyond EOF", name_, fileOffset));
    std::memcpy(data_.data() + fileOffset, &value, 8);
}

uint64_t MachImage::ReadPointer(uint64_t fileOffset) const {
    if (fileOffset + 8 > data_.size())
        throw std::runtime_error(std::format("{}: ReadPointer at {:#x} beyond EOF", name_, fileOffset));
    uint64_t v;
    std::memcpy(&v, data_.data() + fileOffset, 8);
    return v;
}
