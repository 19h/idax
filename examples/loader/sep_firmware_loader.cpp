#include <ida/idax.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace {

// ============================================================================
// Formatting utility
// ============================================================================

template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buffer[2048];
    std::snprintf(buffer, sizeof(buffer), pattern, std::forward<Args>(args)...);
    return buffer;
}

// ============================================================================
// Mach-O load command constants
// ============================================================================

namespace lc {

constexpr std::uint32_t kSegment       = 0x00000001;
constexpr std::uint32_t kSymtab        = 0x00000002;
constexpr std::uint32_t kUnixThread    = 0x00000005;
constexpr std::uint32_t kLoadDylib     = 0x0000000C;
constexpr std::uint32_t kIdDylib       = 0x0000000D;
constexpr std::uint32_t kLoadDylinker  = 0x0000000E;
constexpr std::uint32_t kIdDylinker    = 0x0000000F;
constexpr std::uint32_t kSegment64     = 0x00000019;
constexpr std::uint32_t kUuid          = 0x0000001B;
constexpr std::uint32_t kCodeSignature = 0x0000001D;
constexpr std::uint32_t kSegSplitInfo  = 0x0000001E;
constexpr std::uint32_t kDyldInfo      = 0x00000022;
constexpr std::uint32_t kFuncStarts    = 0x00000026;
constexpr std::uint32_t kDataInCode    = 0x00000029;
constexpr std::uint32_t kSourceVersion = 0x0000002A;
constexpr std::uint32_t kBuildVersion  = 0x00000032;
constexpr std::uint32_t kDysymtab      = 0x0000000B;
constexpr std::uint32_t kMain          = 0x80000028;
constexpr std::uint32_t kDyldInfoOnly  = 0x80000022;
constexpr std::uint32_t kDyldExportsTrie = 0x80000033;
constexpr std::uint32_t kChainedFixups   = 0x80000034;

// SEP-specific load commands
constexpr std::uint32_t kSepSegment        = 0x80000001;
constexpr std::uint32_t kSepShlibChain     = 0x08000001;
constexpr std::uint32_t kSepChainedFixup   = 0x08000002;
constexpr std::uint32_t kSepPrebindSlide   = 0x08000003;

} // namespace lc

// ============================================================================
// Mach-O magic values and layout constants
// ============================================================================

namespace macho {

constexpr std::uint32_t kMagic64     = 0xFEEDFACF;
constexpr std::uint32_t kMagic32     = 0xFEEDFACE;
constexpr std::size_t   kHeaderSize64 = 32;
constexpr std::size_t   kHeaderSize32 = 28;
constexpr std::size_t   kSection64Size = 80;
constexpr std::size_t   kSegCmd64MinSize = 72;
constexpr std::size_t   kNlist64Size = 16;

} // namespace macho

// ============================================================================
// SEP firmware constants
// ============================================================================

namespace sep {

constexpr ida::Address  kRelocStep     = 0x100000000ULL;
constexpr std::size_t   kHdrSize       = 224;
constexpr std::size_t   kApp64BaseSize = 128;
constexpr std::size_t   kLegionSignatureOff1 = 0x103C;
constexpr std::size_t   kLegionSignatureOff2 = 0x1004;
constexpr char          kLegionSignature[]   = "Built by legion2";
constexpr std::size_t   kLegionSignatureLen  = 16;
constexpr std::size_t   kMinProbeSize  = 0x1100;
constexpr std::size_t   kOldHdrOffset  = 0x10F8;

} // namespace sep

// ============================================================================
// Cursor-based binary reader
// ============================================================================

class BinaryReader {
public:
    explicit BinaryReader(std::span<const std::uint8_t> data, std::size_t offset = 0)
        : data_(data), pos_(offset) {}

    [[nodiscard]] std::size_t pos() const { return pos_; }
    [[nodiscard]] std::size_t remaining() const { return pos_ < data_.size() ? data_.size() - pos_ : 0; }
    [[nodiscard]] bool can_read(std::size_t n) const { return pos_ + n <= data_.size(); }

    void seek(std::size_t offset) { pos_ = offset; }
    void skip(std::size_t n) { pos_ += n; }

    std::uint16_t u16() {
        auto v = read_u16_at(data_, pos_);
        pos_ += 2;
        return v;
    }

    std::uint32_t u32() {
        auto v = read_u32_at(data_, pos_);
        pos_ += 4;
        return v;
    }

    std::uint64_t u64() {
        auto v = read_u64_at(data_, pos_);
        pos_ += 8;
        return v;
    }

    void read_into(std::uint8_t* dst, std::size_t n) {
        if (pos_ + n <= data_.size())
            std::memcpy(dst, data_.data() + pos_, n);
        pos_ += n;
    }

    template <std::size_t N>
    std::array<std::uint8_t, N> bytes() {
        std::array<std::uint8_t, N> out{};
        read_into(out.data(), N);
        return out;
    }

    // Static helpers for random-access reads (used throughout parsing)
    static std::uint16_t read_u16_at(std::span<const std::uint8_t> d, std::size_t off) {
        if (off + 2 > d.size()) return 0;
        return static_cast<std::uint16_t>(d[off]) |
               (static_cast<std::uint16_t>(d[off + 1]) << 8);
    }

    static std::uint32_t read_u32_at(std::span<const std::uint8_t> d, std::size_t off) {
        if (off + 4 > d.size()) return 0;
        return static_cast<std::uint32_t>(d[off]) |
               (static_cast<std::uint32_t>(d[off + 1]) << 8) |
               (static_cast<std::uint32_t>(d[off + 2]) << 16) |
               (static_cast<std::uint32_t>(d[off + 3]) << 24);
    }

    static std::uint64_t read_u64_at(std::span<const std::uint8_t> d, std::size_t off) {
        if (off + 8 > d.size()) return 0;
        return static_cast<std::uint64_t>(read_u32_at(d, off)) |
               (static_cast<std::uint64_t>(read_u32_at(d, off + 4)) << 32);
    }

private:
    std::span<const std::uint8_t> data_;
    std::size_t pos_;
};

// Convenience aliases for random-access reads without a cursor
inline std::uint32_t read_u32_le(std::span<const std::uint8_t> d, std::size_t off) {
    return BinaryReader::read_u32_at(d, off);
}

inline std::uint64_t read_u64_le(std::span<const std::uint8_t> d, std::size_t off) {
    return BinaryReader::read_u64_at(d, off);
}

// ============================================================================
// String extraction helpers
// ============================================================================

std::string c_string(std::span<const std::uint8_t> bytes) {
    std::size_t end = 0;
    while (end < bytes.size() && bytes[end] != 0)
        ++end;
    return std::string(reinterpret_cast<const char*>(bytes.data()), end);
}

/// Extract a C string, trim trailing spaces, truncate at first internal space.
std::string c_string_trimmed(std::span<const std::uint8_t> bytes) {
    std::string text = c_string(bytes);
    while (!text.empty() && text.back() == ' ')
        text.pop_back();
    if (auto split = text.find(' '); split != std::string::npos)
        text.resize(split);
    return text;
}

std::string hex_uuid(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 16) return {};
    return fmt(
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[3], bytes[2], bytes[1], bytes[0],
        bytes[5], bytes[4],
        bytes[7], bytes[6],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

/// Sanitize a raw symbol name into a valid IDA identifier.
std::string safe_symbol_name(std::string_view raw, std::string_view fallback) {
    std::string name(raw);
    if (!name.empty() && name.front() == '_')
        name.erase(name.begin());
    for (char& ch : name) {
        bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                  (ch >= '0' && ch <= '9') || ch == '_';
        if (!ok) ch = '_';
    }
    if (name.empty())
        name = std::string(fallback);
    if (name.front() >= '0' && name.front() <= '9')
        name.insert(name.begin(), '_');
    return name;
}

// ============================================================================
// Mach-O identification
// ============================================================================

bool is_macho_64(std::span<const std::uint8_t> data, std::size_t offset = 0) {
    if (offset + 4 > data.size()) return false;
    return read_u32_le(data, offset) == macho::kMagic64;
}

bool is_sep_firmware(std::span<const std::uint8_t> data) {
    if (data.size() < sep::kMinProbeSize)
        return false;
    // Reject DER-encoded (ASN.1) or iBoot images
    if (data[0] == 0x30 && data[1] == 0x83)
        return false;
    if (std::memcmp(data.data() + 8, "eGirBwRD", 8) == 0)
        return false;
    return std::memcmp(data.data() + sep::kLegionSignatureOff1, sep::kLegionSignature, sep::kLegionSignatureLen) == 0 ||
           std::memcmp(data.data() + sep::kLegionSignatureOff2, sep::kLegionSignature, sep::kLegionSignatureLen) == 0;
}

// ============================================================================
// SEP version helpers
// ============================================================================

std::uint32_t srcver_major(std::uint64_t srcver) {
    return static_cast<std::uint32_t>((srcver >> 40) & 0xFFFFFFULL);
}

std::uint32_t sepapp_stride(std::uint32_t srcver, bool is_old) {
    std::uint32_t size = sep::kApp64BaseSize;
    if (is_old)   size -= 24;
    if (srcver < 1300) size -= 8;
    if (srcver >= 2000)      size += 36;
    else if (srcver >= 1700) size += 4;
    return size;
}

// ============================================================================
// Mach-O total file size from LC_SEGMENT_64 extents
// ============================================================================

std::uint64_t calc_macho_file_extent(std::span<const std::uint8_t> data) {
    if (data.size() < 1024 || read_u32_le(data, 0) != macho::kMagic64)
        return 0;

    const std::uint32_t ncmds = read_u32_le(data, 16);
    std::size_t p = macho::kHeaderSize64;
    std::uint64_t extent = 0;

    for (std::uint32_t i = 0; i < ncmds && p + 8 <= data.size(); ++i) {
        const std::uint32_t cmd = read_u32_le(data, p);
        const std::uint32_t csz = read_u32_le(data, p + 4);
        if (csz < 8 || p + csz > data.size()) break;

        if (cmd == lc::kSegment64 && csz >= 56) {
            std::uint64_t fileoff  = read_u64_le(data, p + 40);
            std::uint64_t filesize = read_u64_le(data, p + 48);
            extent = std::max(extent, fileoff + filesize);
        }
        p += csz;
    }
    return extent;
}

// ============================================================================
// SEP module descriptor (parsed from firmware header)
// ============================================================================

struct SepModule {
    std::string   kind;       // "boot", "kernel", "sepos", "app", "shlib"
    std::string   name;
    std::string   uuid;
    std::uint64_t phys_text{};
    std::uint64_t size_text{};
    std::uint64_t phys_data{};
    std::uint64_t size_data{};
    std::uint64_t virt{};
    std::uint64_t ventry{};
    bool          is_macho{};
    bool          is_shlib{};
    std::uint32_t slot{};     // relocation slot index (module_base = kRelocStep * slot)
};

// ============================================================================
// SEP firmware header parsing
// ============================================================================

struct SepHeaderInfo {
    std::array<std::uint8_t, 16> kernel_uuid{};
    std::uint64_t kernel_base_paddr{};
    std::uint64_t kernel_max_paddr{};
    std::uint64_t init_base_paddr{};
    std::uint64_t init_base_vaddr{};
    std::uint64_t init_vsize{};
    std::uint64_t init_ventry{};
    std::array<std::uint8_t, 16> init_name{};
    std::array<std::uint8_t, 16> init_uuid{};
    std::uint64_t srcver{};
    std::uint32_t n_apps{};
    std::uint32_t n_shlibs{};
    std::size_t   apps_off{};
};

struct SepAppInfo {
    std::uint64_t phys_text{};
    std::uint64_t size_text{};
    std::uint64_t phys_data{};
    std::uint64_t size_data{};
    std::uint64_t virt{};
    std::uint64_t ventry{};
    std::array<std::uint8_t, 16> app_name{};
    std::array<std::uint8_t, 16> app_uuid{};
};

/// Locate the SEP boot-args structure offset and subversion.
ida::Result<std::pair<std::size_t, int>> find_legion_header(std::span<const std::uint8_t> data) {
    // Layout variant 1: legion signature at 0x103C (newer)
    if (std::memcmp(data.data() + sep::kLegionSignatureOff1, sep::kLegionSignature, sep::kLegionSignatureLen) == 0) {
        BinaryReader r(data, 0x1000 + 8 + 4 + 8 + 4 + 16 + 8 + 8);
        std::uint32_t subversion = r.u32();
        r.skip(16);
        std::uint16_t structoff = r.u16();
        return std::pair{static_cast<std::size_t>(structoff), static_cast<int>(subversion)};
    }

    // Layout variant 2: legion signature at 0x1004 (older)
    if (std::memcmp(data.data() + sep::kLegionSignatureOff2, sep::kLegionSignature, sep::kLegionSignatureLen) == 0) {
        BinaryReader r(data, 0x1000);
        std::uint32_t subversion = r.u32();
        r.skip(16);
        std::uint16_t structoff = r.u16();
        if (structoff == 0) structoff = 0xFFFF;
        return std::pair{static_cast<std::size_t>(structoff), static_cast<int>(subversion)};
    }

    return std::unexpected(ida::Error::validation("Unrecognised or unsupported SEP firmware image"));
}

/// Parse the v3/v4 SEP root header starting at `hdr_offset`.
ida::Result<SepHeaderInfo>
parse_sep_root_header(std::span<const std::uint8_t> data, std::size_t hdr_offset,
                      int ver, bool is_old) {
    if (hdr_offset + sep::kHdrSize > data.size())
        return std::unexpected(ida::Error::validation("SEP header is truncated", std::to_string(hdr_offset)));

    BinaryReader r(data, hdr_offset);
    SepHeaderInfo hdr;

    hdr.kernel_uuid = r.bytes<16>();
    r.skip(8);  // kern_heap_size
    hdr.kernel_base_paddr = r.u64();
    hdr.kernel_max_paddr  = r.u64();
    r.skip(8 * 5);  // app_ro_start, app_ro_end, end_of_payload, required_tz0, required_tz1

    std::uint64_t ar_min_size = r.u64();
    if (ar_min_size != 0 || ver == 4)
        r.skip(8 * 3);  // non_ar_plaintext, shm_base, shm_size

    hdr.init_base_paddr = r.u64();
    hdr.init_base_vaddr = r.u64();
    hdr.init_vsize      = r.u64();
    hdr.init_ventry     = r.u64();
    r.skip(8 * 2);  // stack_phys_base, stack_virt_base

    std::uint64_t stack_size = r.u64();
    if (stack_size != 0 || ver == 4)
        r.skip(8 * 3);  // normal_memory, non_ar_memory, heap_memory

    if (ver == 4)
        r.skip(4 + 4 + 8 * 3);  // virtual_memory, dart_memory, thread_count, cnode_count + padding

    hdr.init_name = r.bytes<16>();
    hdr.init_uuid = r.bytes<16>();

    if (!is_old)
        hdr.srcver = r.u64();

    r.skip(4 + 1);  // crc32 + kern_no_ar_mem flag

    if (!r.can_read(3))
        return std::unexpected(ida::Error::validation("SEP header padding is truncated", std::to_string(r.pos())));

    // Check for dynamic-objects padding block
    std::array<std::uint8_t, 3> pad;
    r.read_into(pad.data(), 3);
    if (pad == std::array<std::uint8_t, 3>{0x40, 0x04, 0x00})
        r.skip(0x100);

    hdr.n_apps   = r.u32();
    hdr.n_shlibs = r.u32();
    hdr.apps_off = r.pos();
    return hdr;
}

/// Parse a single SEP app/shlib entry.
SepAppInfo parse_sep_app_entry(std::span<const std::uint8_t> data, std::size_t off,
                               int ver, bool is_old) {
    BinaryReader r(data, off);
    SepAppInfo app;

    app.phys_text = r.u64();
    app.size_text = r.u64();
    app.phys_data = r.u64();
    app.size_data = r.u64();
    app.virt      = r.u64();
    app.ventry    = r.u64();

    std::uint64_t stack_size = r.u64();
    if (!is_old)
        r.skip(8 * 2);  // mem_size, non_ar_mem_size
    if (stack_size != 0 || ver == 4)
        r.skip(8);       // heap_mem_size
    if (ver == 4)
        r.skip(8 * 4);  // unk fields
    r.skip(4 + 4);      // compact_ver_start, compact_ver_end

    app.app_name = r.bytes<16>();
    app.app_uuid = r.bytes<16>();
    return app;
}

// ============================================================================
// Module extraction: v2 (legacy) path
// ============================================================================

std::vector<SepModule>
extract_modules_v2(std::span<const std::uint8_t> data, std::size_t hdr_offset) {
    BinaryReader r(data, hdr_offset);

    r.skip(16);  // uuid
    std::uint64_t kbase = r.u64();
    r.skip(8);   // kmax
    r.skip(8 * 3);

    std::uint64_t ibase  = r.u64();
    std::uint64_t ivaddr = r.u64();
    std::uint64_t ivsize = r.u64();
    std::uint64_t ivery  = r.u64();
    r.skip(8 * 3);

    auto iname = r.bytes<16>();
    auto iuuid = r.bytes<16>();
    r.skip(4 + 1 + 3);

    std::uint32_t n_apps   = r.u32();
    std::uint32_t n_shlibs = r.u32();

    std::uint64_t ksize = calc_macho_file_extent(data.subspan(0x4000));
    std::string sepos_name = c_string_trimmed(iname);
    if (sepos_name.empty()) sepos_name = "SEPOS";

    std::vector<SepModule> modules;
    modules.push_back({"boot",   "BOOTER", {},                  0,     0x1000, 0, 0, 0,      0,     false, false, 0});
    modules.push_back({"kernel", "kernel", {},                  0x4000, ksize, 0, 0, 0x4000, 0x4000,
                        is_macho_64(data, 0x4000), false, 0});
    modules.push_back({"sepos",  sepos_name, hex_uuid(iuuid),  ibase, ivsize, 0, 0, ivaddr, ivery,
                        is_macho_64(data, static_cast<std::size_t>(ibase)), false, 1});

    // v2 app entries: fixed stride 0x58, starting at 0x1198
    constexpr std::size_t kV2Stride = 0x58;
    std::size_t off = 0x1198;
    for (std::uint32_t i = 0; i < n_apps + n_shlibs; ++i, off += kV2Stride) {
        std::uint64_t phys_text = read_u64_le(data, off);
        std::uint64_t virt      = read_u64_le(data, off + 8);
        std::uint64_t size_text = read_u64_le(data, off + 16);
        std::uint64_t ventry    = read_u64_le(data, off + 24);
        std::array<std::uint8_t, 16> app_name{}, app_uuid{};
        std::memcpy(app_name.data(), data.data() + off + 48, 16);
        std::memcpy(app_uuid.data(), data.data() + off + 64, 16);

        bool shlib = (i >= n_apps);
        modules.push_back({
            shlib ? "shlib" : "app",
            c_string_trimmed(app_name),
            hex_uuid(app_uuid),
            phys_text, size_text, 0, 0, virt, ventry,
            is_macho_64(data, static_cast<std::size_t>(phys_text)),
            shlib,
            i + 2,
        });
    }
    return modules;
}

// ============================================================================
// Module extraction: v3/v4 path
// ============================================================================

ida::Result<std::vector<SepModule>>
extract_modules_v3v4(std::span<const std::uint8_t> data, std::size_t hdr_offset,
                     int ver, bool is_old) {
    auto hdr = parse_sep_root_header(data, hdr_offset, ver, is_old);
    if (!hdr) return std::unexpected(hdr.error());

    std::size_t   apps_off = hdr->apps_off;
    std::uint32_t n_apps   = hdr->n_apps;
    std::uint32_t n_shlibs = hdr->n_shlibs;

    // Fallback: if n_apps == 0, the app list starts 0x100 bytes later
    if (n_apps == 0) {
        apps_off += 0x100;
        n_apps   = read_u32_le(data, hdr_offset + 0x210);
        n_shlibs = read_u32_le(data, hdr_offset + 0x214);
    }

    // Compute kernel size from Mach-O extents or header range
    std::uint64_t ksize = 0;
    if (hdr->kernel_base_paddr < data.size())
        ksize = calc_macho_file_extent(data.subspan(static_cast<std::size_t>(hdr->kernel_base_paddr)));
    if (ksize == 0 && hdr->kernel_max_paddr > hdr->kernel_base_paddr)
        ksize = hdr->kernel_max_paddr - hdr->kernel_base_paddr;

    std::vector<SepModule> modules;

    // Boot region: file offset 0 → kernel_base_paddr
    modules.push_back({"boot", "SEPBOOT", {},
                       0, hdr->kernel_base_paddr, 0, 0, 0, 0, false, false, 0});

    // Kernel
    modules.push_back({"kernel", "kernel", hex_uuid(hdr->kernel_uuid),
                       hdr->kernel_base_paddr, ksize, 0, 0,
                       hdr->kernel_base_paddr, hdr->kernel_base_paddr,
                       is_macho_64(data, static_cast<std::size_t>(hdr->kernel_base_paddr)),
                       false, 0});

    // SEPOS init task
    std::string sepos_name = c_string_trimmed(hdr->init_name);
    if (sepos_name.empty()) sepos_name = "SEPOS";
    std::uint64_t sepos_size = 0;
    if (hdr->init_base_paddr < data.size())
        sepos_size = calc_macho_file_extent(data.subspan(static_cast<std::size_t>(hdr->init_base_paddr)));
    if (sepos_size == 0) sepos_size = hdr->init_vsize;
    modules.push_back({"sepos", sepos_name, hex_uuid(hdr->init_uuid),
                       hdr->init_base_paddr, sepos_size, 0, 0,
                       hdr->init_base_vaddr, hdr->init_ventry,
                       is_macho_64(data, static_cast<std::size_t>(hdr->init_base_paddr)),
                       false, 1});

    // App and shared library entries
    const std::uint32_t stride = sepapp_stride(srcver_major(hdr->srcver), is_old);
    std::size_t off = apps_off;

    auto emit_entries = [&](std::uint32_t count, bool shlib, std::uint32_t base_slot) {
        for (std::uint32_t i = 0; i < count; ++i, off += stride) {
            auto app = parse_sep_app_entry(data, off, ver, is_old);
            modules.push_back({
                shlib ? "shlib" : "app",
                c_string_trimmed(app.app_name),
                hex_uuid(app.app_uuid),
                app.phys_text, app.size_text, app.phys_data, app.size_data,
                app.virt, app.ventry,
                is_macho_64(data, static_cast<std::size_t>(app.phys_text)),
                shlib,
                base_slot + i,
            });
        }
    };

    emit_entries(n_apps,   false, 2);
    emit_entries(n_shlibs, true,  n_apps + 2);

    return modules;
}

/// Top-level module extraction dispatcher.
ida::Result<std::vector<SepModule>> extract_all_modules(std::span<const std::uint8_t> data) {
    auto hdr_info = find_legion_header(data);
    if (!hdr_info) return std::unexpected(hdr_info.error());

    auto [hdr_offset_raw, ver] = *hdr_info;

    if (ver == 1)
        return std::unexpected(ida::Error::validation("32-bit SEP firmware is not supported"));

    bool is_old = (hdr_offset_raw == 0xFFFF);
    std::size_t hdr_offset = is_old ? sep::kOldHdrOffset : hdr_offset_raw;

    if (ver == 2)
        return extract_modules_v2(data, hdr_offset);

    return extract_modules_v3v4(data, hdr_offset, ver, is_old);
}

// ============================================================================
// Mach-O parsing structures
// ============================================================================

struct MachOSection {
    std::string   name;
    std::string   segment_name;
    std::uint64_t address{};
    std::uint64_t size{};
    std::uint32_t offset{};
    std::uint32_t flags{};
};

struct MachOSegment {
    std::string   name;
    std::uint64_t vmaddr{};
    std::uint64_t vmsize{};
    std::uint64_t fileoff{};
    std::uint64_t filesize{};
    std::uint32_t initprot{};
    std::vector<MachOSection> sections;
};

struct MachOBinary {
    std::uint64_t imagebase{};
    std::vector<MachOSegment> segments;
    std::optional<std::uint64_t> entry_pc;
    std::optional<std::uint64_t> entry_main;
    std::vector<std::pair<std::string, std::uint64_t>> symbols;
};

// ============================================================================
// Mach-O parsing
// ============================================================================

std::vector<MachOSection>
parse_sections_64(std::span<const std::uint8_t> data, std::size_t base, std::uint32_t count) {
    std::vector<MachOSection> sections;
    sections.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::size_t p = base + static_cast<std::size_t>(i) * macho::kSection64Size;
        if (p + macho::kSection64Size > data.size()) break;
        sections.push_back({
            c_string(data.subspan(p, 16)),
            c_string(data.subspan(p + 16, 16)),
            read_u64_le(data, p + 32),
            read_u64_le(data, p + 40),
            read_u32_le(data, p + 48),
            read_u32_le(data, p + 64),
        });
    }
    return sections;
}

std::vector<std::pair<std::string, std::uint64_t>>
parse_nlist64_symbols(std::span<const std::uint8_t> data,
                      std::optional<std::uint32_t> symoff, std::uint32_t nsyms,
                      std::optional<std::uint32_t> stroff) {
    if (!symoff || !stroff || nsyms == 0) return {};

    std::vector<std::pair<std::string, std::uint64_t>> symbols;
    for (std::uint32_t i = 0; i < nsyms; ++i) {
        std::size_t off = static_cast<std::size_t>(*symoff) + static_cast<std::size_t>(i) * macho::kNlist64Size;
        if (off + macho::kNlist64Size > data.size()) break;

        std::uint32_t strx  = read_u32_le(data, off);
        std::uint64_t value = read_u64_le(data, off + 8);
        if (value == 0) continue;

        std::size_t str_start = static_cast<std::size_t>(*stroff) + strx;
        if (str_start >= data.size()) continue;

        auto name = c_string(data.subspan(str_start));
        if (!name.empty())
            symbols.emplace_back(std::move(name), value);
    }
    return symbols;
}

std::optional<MachOBinary> parse_macho(std::span<const std::uint8_t> data) {
    if (data.size() < macho::kHeaderSize64) return std::nullopt;
    if (read_u32_le(data, 0) != macho::kMagic64) return std::nullopt;

    const std::uint32_t ncmds = read_u32_le(data, 16);
    std::size_t p = macho::kHeaderSize64;

    std::vector<MachOSegment>    segments;
    std::optional<std::uint64_t> entry_pc, entry_main;
    std::optional<std::uint32_t> symoff, stroff;
    std::uint32_t nsyms = 0;

    for (std::uint32_t i = 0; i < ncmds && p + 8 <= data.size(); ++i) {
        const std::uint32_t cmd = read_u32_le(data, p);
        const std::uint32_t csz = read_u32_le(data, p + 4);
        if (csz < 8 || p + csz > data.size()) break;

        switch (cmd) {
        case lc::kSegment64:
            if (csz >= macho::kSegCmd64MinSize) {
                auto nsects = read_u32_le(data, p + 64);
                segments.push_back({
                    c_string(data.subspan(p + 8, 16)),
                    read_u64_le(data, p + 24),  // vmaddr
                    read_u64_le(data, p + 32),  // vmsize
                    read_u64_le(data, p + 40),  // fileoff
                    read_u64_le(data, p + 48),  // filesize
                    read_u32_le(data, p + 60),  // initprot
                    parse_sections_64(data, p + 72, nsects),
                });
            }
            break;

        case lc::kUnixThread: {
            constexpr std::size_t kPC_Offset = 16 + 256;  // ARM thread state PC offset
            if (p + kPC_Offset + 8 <= data.size())
                entry_pc = read_u64_le(data, p + kPC_Offset);
            break;
        }

        case lc::kMain:
            if (csz >= 24)
                entry_main = read_u64_le(data, p + 8);
            break;

        case lc::kSymtab:
            if (csz >= 24) {
                symoff = read_u32_le(data, p + 8);
                nsyms  = read_u32_le(data, p + 12);
                stroff = read_u32_le(data, p + 16);
            }
            break;

        default: break;
        }
        p += csz;
    }

    // Compute imagebase: lowest vmaddr of non-PAGEZERO segments
    std::uint64_t imagebase = 0;
    bool found = false;
    for (const auto& seg : segments) {
        if (seg.name == "__PAGEZERO") continue;
        if (!found || seg.vmaddr < imagebase) {
            imagebase = seg.vmaddr;
            found = true;
        }
    }

    return MachOBinary{
        imagebase,
        std::move(segments),
        entry_pc,
        entry_main,
        parse_nlist64_symbols(data, symoff, nsyms, stroff),
    };
}

/// Scan load commands for LC_SEP_SEGMENT and return its data offset field.
std::optional<std::uint32_t> find_lc_sep_slide(std::span<const std::uint8_t> data) {
    if (data.size() < macho::kHeaderSize64) return std::nullopt;
    auto magic = read_u32_le(data, 0);
    if (magic != macho::kMagic64 && magic != macho::kMagic32) return std::nullopt;

    bool is64 = (magic == macho::kMagic64);
    std::uint32_t ncmds = read_u32_le(data, 16);
    std::size_t p = is64 ? macho::kHeaderSize64 : macho::kHeaderSize32;

    for (std::uint32_t i = 0; i < ncmds && p + 8 <= data.size(); ++i) {
        std::uint32_t cmd = read_u32_le(data, p);
        std::uint32_t csz = read_u32_le(data, p + 4);
        if (csz < 8 || p + csz > data.size()) break;
        if (cmd == lc::kSepSegment && csz >= 16)
            return read_u32_le(data, p + 8);
        p += csz;
    }
    return std::nullopt;
}

std::uint64_t compute_shared_cache_slide(std::uint32_t lc_sep_dataoff, std::uint64_t imagebase) {
    return static_cast<std::uint64_t>(lc_sep_dataoff & 0xFFFFF) - imagebase;
}

// ============================================================================
// Shared library resolution state
// ============================================================================

struct SharedLibraryInfo {
    ida::Address  base{0};
    std::uint64_t slide{0};
};

// ============================================================================
// IDA type helpers
// ============================================================================

ida::type::TypeInfo u8_type()  { return ida::type::TypeInfo::uint8(); }
ida::type::TypeInfo u16_type() { return ida::type::TypeInfo::uint16(); }
ida::type::TypeInfo u32_type() { return ida::type::TypeInfo::uint32(); }
ida::type::TypeInfo u64_type() { return ida::type::TypeInfo::uint64(); }
ida::type::TypeInfo i32_type() { return ida::type::TypeInfo::int32(); }
ida::type::TypeInfo char16_type() { return ida::type::TypeInfo::array_of(u8_type(), 16); }

using MemberSpec = std::tuple<std::size_t, std::string, ida::type::TypeInfo>;

ida::Status save_named_struct(std::string_view name, const std::vector<MemberSpec>& members) {
    auto st = ida::type::TypeInfo::create_struct();
    for (const auto& [offset, member_name, member_type] : members) {
        auto s = st.add_member(member_name, member_type, offset);
        if (!s) return s;
    }
    return st.save_as(name);
}

ida::Status apply_type_at(ida::Address ea, const ida::type::TypeInfo& type) {
    auto sz = type.size();
    if (!sz) return std::unexpected(sz.error());
    if (*sz == 0) return ida::ok();
    auto u = ida::data::undefine(ea, *sz);
    if (!u) return u;
    return type.apply(ea);
}

ida::Status apply_named_type_at(ida::Address ea, std::string_view name) {
    auto type = ida::type::TypeInfo::by_name(name);
    if (!type) return std::unexpected(type.error());
    return apply_type_at(ea, *type);
}

// ============================================================================
// Segment property derivation
// ============================================================================

ida::segment::Permissions permissions_for(std::uint32_t prot) {
    return {
        .read    = true,
        .write   = (prot & 0x2U) != 0,
        .execute = (prot & 0x4U) != 0,
    };
}

ida::segment::Type segment_type_for(const MachOSegment& seg) {
    if (seg.initprot & 0x4U)                        return ida::segment::Type::Code;
    if (seg.filesize == 0 && seg.vmsize > 0)         return ida::segment::Type::Bss;
    return ida::segment::Type::Data;
}

std::string segment_class_for(const MachOSegment& seg) {
    if (seg.initprot & 0x4U)                        return "CODE";
    if (seg.filesize == 0 && seg.vmsize > 0)         return "BSS";
    if (seg.initprot & 0x2U)                        return "DATA";
    return "CONST";
}

ida::Status create_or_update_segment(ida::Address start, ida::Address end,
                                     std::string_view name, std::string_view class_name,
                                     ida::segment::Type type,
                                     ida::segment::Permissions perms) {
    auto s = ida::segment::create(start, end, name, class_name, type);
    if (!s) return std::unexpected(s.error());
    auto b = ida::segment::set_bitness(start, 64);
    if (!b) return b;
    return ida::segment::set_permissions(start, perms);
}

// ============================================================================
// Mach-O load command → IDA type name mapping
// ============================================================================

std::string load_command_type_name(std::uint32_t cmd) {
    switch (cmd) {
    case lc::kSymtab:          return "symtab_command";
    case lc::kDysymtab:        return "dysymtab_command";
    case lc::kLoadDylib:
    case lc::kIdDylib:         return "dylib_command";
    case lc::kLoadDylinker:
    case lc::kIdDylinker:      return "dylinker_command";
    case lc::kSegment64:       return "segment_command_64";
    case lc::kUuid:            return "uuid_command";
    case lc::kCodeSignature:
    case lc::kSegSplitInfo:
    case lc::kFuncStarts:
    case lc::kDataInCode:
    case lc::kDyldExportsTrie:
    case lc::kChainedFixups:   return "linkedit_data_command";
    case lc::kDyldInfo:
    case lc::kDyldInfoOnly:    return "dyld_info_command";
    case lc::kSourceVersion:   return "source_version_command";
    case lc::kBuildVersion:    return "build_version_command";
    case lc::kMain:            return "entry_point_command";
    case lc::kSepShlibChain:   return "sep_shlib_chain_command";
    case lc::kSepChainedFixup: return "sep_chained_fixup_command";
    case lc::kSepPrebindSlide: return "sep_prebind_slide_command";
    default:                   return "load_command";
    }
}

// ============================================================================
// Mach-O header + load command type annotation
// ============================================================================

ida::Status define_macho_header_types() {
    auto status = save_named_struct("mach_header_64", {
        {0,  "magic",      u32_type()}, {4,  "cputype",    i32_type()},
        {8,  "cpusubtype", i32_type()}, {12, "filetype",   u32_type()},
        {16, "ncmds",      u32_type()}, {20, "sizeofcmds", u32_type()},
        {24, "flags",      u32_type()}, {28, "reserved",   u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("load_command", {
        {0, "cmd", u32_type()}, {4, "cmdsize", u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("segment_command_64", {
        {0,  "cmd",      u32_type()},    {4,  "cmdsize",  u32_type()},
        {8,  "segname",  char16_type()}, {24, "vmaddr",   u64_type()},
        {32, "vmsize",   u64_type()},    {40, "fileoff",  u64_type()},
        {48, "filesize", u64_type()},    {56, "maxprot",  i32_type()},
        {60, "initprot", i32_type()},    {64, "nsects",   u32_type()},
        {68, "flags",    u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("section_64", {
        {0,  "sectname",  char16_type()}, {16, "segname",   char16_type()},
        {32, "addr",      u64_type()},    {40, "size",      u64_type()},
        {48, "offset",    u32_type()},    {52, "align",     u32_type()},
        {56, "reloff",    u32_type()},    {60, "nreloc",    u32_type()},
        {64, "flags",     u32_type()},    {68, "reserved1", u32_type()},
        {72, "reserved2", u32_type()},    {76, "reserved3", u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("symtab_command", {
        {0, "cmd", u32_type()},  {4, "cmdsize", u32_type()}, {8,  "symoff",  u32_type()},
        {12, "nsyms", u32_type()}, {16, "stroff", u32_type()}, {20, "strsize", u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("dysymtab_command", {
        {0,  "cmd", u32_type()},       {4,  "cmdsize", u32_type()},
        {8,  "ilocalsym", u32_type()}, {12, "nlocalsym", u32_type()},
        {16, "iextdefsym", u32_type()},{20, "nextdefsym", u32_type()},
        {24, "iundefsym", u32_type()}, {28, "nundefsym", u32_type()},
        {32, "tocoff", u32_type()},    {36, "ntoc", u32_type()},
        {40, "modtaboff", u32_type()}, {44, "nmodtab", u32_type()},
        {48, "extrefsymoff", u32_type()}, {52, "nextrefsyms", u32_type()},
        {56, "indirectsymoff", u32_type()}, {60, "nindirectsyms", u32_type()},
        {64, "extreloff", u32_type()}, {68, "nextrel", u32_type()},
        {72, "locreloff", u32_type()}, {76, "nlocrel", u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("dylib_command", {
        {0, "cmd", u32_type()}, {4, "cmdsize", u32_type()}, {8, "name", u32_type()},
        {12, "timestamp", u32_type()}, {16, "current_version", u32_type()},
        {20, "compatibility_version", u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("dylinker_command", {
        {0, "cmd", u32_type()}, {4, "cmdsize", u32_type()}, {8, "name", u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("uuid_command", {
        {0, "cmd", u32_type()}, {4, "cmdsize", u32_type()}, {8, "uuid", char16_type()},
    });
    if (!status) return status;

    status = save_named_struct("entry_point_command", {
        {0, "cmd", u32_type()}, {4, "cmdsize", u32_type()},
        {8, "entryoff", u64_type()}, {16, "stacksize", u64_type()},
    });
    if (!status) return status;

    status = save_named_struct("linkedit_data_command", {
        {0, "cmd", u32_type()}, {4, "cmdsize", u32_type()},
        {8, "dataoff", u32_type()}, {12, "datasize", u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("source_version_command", {
        {0, "cmd", u32_type()}, {4, "cmdsize", u32_type()}, {8, "version", u64_type()},
    });
    if (!status) return status;

    status = save_named_struct("build_version_command", {
        {0, "cmd", u32_type()}, {4, "cmdsize", u32_type()}, {8, "platform", u32_type()},
        {12, "minos", u32_type()}, {16, "sdk", u32_type()}, {20, "ntools", u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("build_tool_version", {
        {0, "tool", u32_type()}, {4, "version", u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("dyld_info_command", {
        {0, "cmd", u32_type()},  {4, "cmdsize", u32_type()},
        {8,  "rebase_off", u32_type()},  {12, "rebase_size", u32_type()},
        {16, "bind_off", u32_type()},    {20, "bind_size", u32_type()},
        {24, "weak_bind_off", u32_type()}, {28, "weak_bind_size", u32_type()},
        {32, "lazy_bind_off", u32_type()}, {36, "lazy_bind_size", u32_type()},
        {40, "export_off", u32_type()},  {44, "export_size", u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("sep_shlib_chain_command", {
        {0, "cmd", u32_type()}, {4, "cmdsize", u32_type()},
        {8, "offset", i32_type()}, {12, "flags", u32_type()},
    });
    if (!status) return status;

    status = save_named_struct("sep_chained_fixup_command", {
        {0, "cmd", u32_type()}, {4, "cmdsize", u32_type()}, {8, "flags", u32_type()},
    });
    if (!status) return status;

    return save_named_struct("sep_prebind_slide_command", {
        {0, "cmd", u32_type()}, {4, "cmdsize", u32_type()},
        {8, "slide", i32_type()}, {12, "flags", u32_type()},
    });
}

// ============================================================================
// Load command annotation pass
// ============================================================================

ida::Status annotate_macho_load_commands(ida::Address header_start,
                                         std::span<const std::uint8_t> raw_hdr) {
    if (raw_hdr.size() < macho::kHeaderSize64) return ida::ok();

    const std::uint32_t ncmds = read_u32_le(raw_hdr, 16);
    std::size_t p = macho::kHeaderSize64;

    for (std::uint32_t i = 0; i < ncmds && p + 8 <= raw_hdr.size(); ++i) {
        const std::uint32_t cmd = read_u32_le(raw_hdr, p);
        const std::uint32_t csz = read_u32_le(raw_hdr, p + 4);
        if (csz < 8 || p + csz > raw_hdr.size()) break;

        (void)apply_named_type_at(header_start + p, load_command_type_name(cmd));

        // Annotate section headers within segment commands
        if (cmd == lc::kSegment64 && p + 72 <= raw_hdr.size()) {
            std::uint32_t nsects = read_u32_le(raw_hdr, p + 64);
            for (std::uint32_t s = 0; s < nsects; ++s) {
                std::size_t sect_off = p + 72 + static_cast<std::size_t>(s) * macho::kSection64Size;
                if (sect_off + macho::kSection64Size > raw_hdr.size()) break;
                (void)apply_named_type_at(header_start + sect_off, "section_64");
            }
        }

        // Annotate build tool version entries
        if (cmd == lc::kBuildVersion && p + 24 <= raw_hdr.size()) {
            std::uint32_t ntools = read_u32_le(raw_hdr, p + 20);
            for (std::uint32_t t = 0; t < ntools; ++t) {
                std::size_t tool_off = p + 24 + static_cast<std::size_t>(t) * 8;
                if (tool_off + 8 > raw_hdr.size()) break;
                (void)apply_named_type_at(header_start + tool_off, "build_tool_version");
            }
        }

        // Annotate inline name strings in dylib/dylinker commands
        if ((cmd == lc::kLoadDylib || cmd == lc::kIdDylib ||
             cmd == lc::kLoadDylinker || cmd == lc::kIdDylinker) && p + 12 <= raw_hdr.size()) {
            std::uint32_t name_off = read_u32_le(raw_hdr, p + 8);
            if (name_off < csz && p + name_off < raw_hdr.size()) {
                auto char_array = ida::type::TypeInfo::array_of(u8_type(), csz - name_off);
                (void)apply_type_at(header_start + p + name_off, char_array);
            }
        }

        p += csz;
    }
    return ida::ok();
}

// ============================================================================
// Qword rewriting engine (pointer fixups, GOT resolution, PAC decoding)
// ============================================================================

using QwordRewriter = std::function<std::optional<std::uint64_t>(std::uint64_t)>;

ida::Status rewrite_qwords(ida::Address ea, std::size_t count,
                           const QwordRewriter& fn, bool install_fixups) {
    for (std::size_t i = 0; i < count; ++i) {
        ida::Address slot = ea + static_cast<ida::Address>(i * 8);
        auto cur = ida::data::read_qword(slot);
        if (!cur) continue;

        auto repl = fn(*cur);
        if (!repl) continue;

        auto w = ida::data::write_qword(slot, *repl);
        if (!w) return w;

        auto dq = ida::data::define_qword(slot, 1);
        if (!dq) {
            auto u = ida::data::undefine(slot, 8);
            if (u) dq = ida::data::define_qword(slot, 1);
        }

        if (install_fixups) {
            ida::fixup::Descriptor fx;
            fx.source = slot;
            fx.type   = ida::fixup::Type::Off64;
            fx.base   = 0;
            fx.target = *repl;
            fx.offset = *repl;
            (void)ida::fixup::set(slot, fx);
        }
    }
    return ida::ok();
}

// Named rewriter factories for each fixup strategy
namespace rewriters {

/// Resolve __mod_init_func / __init_offsets / __auth_ptr entries.
QwordRewriter init_pointer(std::uint64_t imagebase) {
    return [=](std::uint64_t orig) -> std::optional<std::uint64_t> {
        if (orig == 0) return std::nullopt;
        if (orig < 0x1'0000'0000ULL) return imagebase + orig;
        return imagebase + (orig & 0xFFFFFFFFULL);
    };
}

/// Resolve __auth_got / __got entries via shared library cache.
QwordRewriter got_shlib(const SharedLibraryInfo& shlib) {
    return [&](std::uint64_t orig) -> std::optional<std::uint64_t> {
        if (orig == 0) return std::nullopt;
        return static_cast<std::uint64_t>(shlib.base + (orig & 0xFFFFFULL) - shlib.slide);
    };
}

/// Decode PAC-tagged pointers in __const sections.
QwordRewriter pac_const(std::uint64_t imagebase, std::uint64_t text_start, std::uint64_t text_end) {
    return [=](std::uint64_t orig) -> std::optional<std::uint64_t> {
        auto pt_type   = (orig >> 48) & 0xFFFFULL;
        auto pt_tag    = (orig >> 32) & 0xFFFFULL;
        auto pt_offset = orig & 0xFFFFFFFFULL;

        if (pt_tag == 0) return std::nullopt;
        if ((pt_type & 0xF000ULL) != 0x8000ULL && (pt_type & 0xF000ULL) != 0x9000ULL)
            return std::nullopt;

        auto target = imagebase + pt_offset;
        if (!(imagebase + text_start <= target && target < imagebase + text_end))
            return std::nullopt;

        return target;
    };
}

} // namespace rewriters

// ============================================================================
// SEP firmware boot-args type definition
// ============================================================================

/// Incrementally builds a struct type via successive member appends.
class StructBuilder {
public:
    explicit StructBuilder(ida::type::TypeInfo type) : type_(std::move(type)) {}

    ida::Status add(std::string_view name, const ida::type::TypeInfo& mtype, std::size_t size) {
        auto s = type_.add_member(name, mtype, off_);
        off_ += size;
        return s;
    }

    ida::Status add_u32(std::string_view name) { return add(name, u32_type(), 4); }
    ida::Status add_u64(std::string_view name) { return add(name, u64_type(), 8); }
    ida::Status add_u16(std::string_view name) { return add(name, u16_type(), 2); }

    ida::Status add_bytes(std::string_view name, std::size_t n) {
        return add(name, ida::type::TypeInfo::array_of(u8_type(), n), n);
    }

    void seek(std::size_t off) { off_ = off; }
    [[nodiscard]] std::size_t pos() const { return off_; }

    ida::Status save(std::string_view name) { return type_.save_as(name); }
    ida::type::TypeInfo& type() { return type_; }

private:
    ida::type::TypeInfo type_;
    std::size_t off_{0};
};

/// Compute firmware file offset for a given segment-relative offset within a module.
std::uint64_t fw_offset_for(std::uint64_t seg_file_offset, const SepModule& mod) {
    if (mod.phys_data == 0 || seg_file_offset < mod.size_text)
        return mod.phys_text + seg_file_offset;
    return mod.phys_data + (seg_file_offset - mod.size_text);
}

ida::Status define_firmware_types(std::span<const std::uint8_t> fw) {
    auto hdr_info = find_legion_header(fw);
    if (!hdr_info) return ida::ok();

    auto [hdr_offset_raw, ver] = *hdr_info;
    if (ver < 3) return ida::ok();

    bool is_old = (hdr_offset_raw == 0xFFFF);
    std::size_t hdr_offset = is_old ? sep::kOldHdrOffset : hdr_offset_raw;
    constexpr ida::Address kBootStart = 0x1000;

    auto hdr = parse_sep_root_header(fw, hdr_offset, ver, is_old);
    if (!hdr) return std::unexpected(hdr.error());

    std::size_t   apps_off = hdr->apps_off;
    std::uint32_t n_apps   = hdr->n_apps;
    std::uint32_t n_shlibs = hdr->n_shlibs;
    if (n_apps == 0) {
        apps_off += 0x100;
        n_apps   = read_u32_le(fw, hdr_offset + 0x210);
        n_shlibs = read_u32_le(fw, hdr_offset + 0x214);
    }
    const std::uint32_t stride = sepapp_stride(srcver_major(hdr->srcver), is_old);

    // --- SEPApp64 struct ---
    {
        auto status = save_named_struct("SEPApp64", {
            {0,  "phys_text",  u64_type()}, {8,  "size_text", u64_type()},
            {16, "phys_data",  u64_type()}, {24, "size_data", u64_type()},
            {32, "virt",       u64_type()}, {40, "ventry",    u64_type()},
            {48, "stack_size", u64_type()},
        });
        if (!status) return status;

        auto sepapp = ida::type::TypeInfo::by_name("SEPApp64");
        if (!sepapp) return std::unexpected(sepapp.error());

        StructBuilder b(std::move(*sepapp));
        b.seek(56);

        if (!is_old) {
            status = b.add_u64("mem_size");        if (!status) return status;
            status = b.add_u64("non_ar_mem_size"); if (!status) return status;
        }
        if (ver == 4) {
            for (auto name : {"heap_mem_size", "_unk1", "_unk2", "_unk3", "_unk4"}) {
                status = b.add_u64(name); if (!status) return status;
            }
        }
        status = b.add_u32("compact_ver_start"); if (!status) return status;
        status = b.add_u32("compact_ver_end");   if (!status) return status;
        status = b.add_bytes("app_name", 16);    if (!status) return status;
        status = b.add_bytes("app_uuid", 16);    if (!status) return status;
        if (!is_old) {
            status = b.add_u64("srcver"); if (!status) return status;
        }
        if (stride > b.pos()) {
            status = b.add_bytes("_pad", stride - b.pos()); if (!status) return status;
        }
        status = b.save("SEPApp64"); if (!status) return status;
    }

    // --- SEPRootserver struct ---
    {
        StructBuilder b(ida::type::TypeInfo::create_struct());
        auto s = b.add_u64("phys_base");        if (!s) return s;
        s = b.add_u64("virt_base");              if (!s) return s;
        s = b.add_u64("virt_size");              if (!s) return s;
        s = b.add_u64("virt_entry");             if (!s) return s;
        s = b.add_u64("stack_phys_base");        if (!s) return s;
        s = b.add_u64("stack_virt_base");        if (!s) return s;
        s = b.add_u64("stack_size");             if (!s) return s;
        if (read_u64_le(fw, hdr_offset + 15 * 8) != 0 || ver == 4) {
            s = b.add_u64("normal_memory_size"); if (!s) return s;
            s = b.add_u64("non_ar_memory_size"); if (!s) return s;
            s = b.add_u64("heap_memory_size");   if (!s) return s;
        }
        if (ver == 4) {
            s = b.add_u64("virtual_memory_size"); if (!s) return s;
            s = b.add_u64("dart_memory_size");    if (!s) return s;
            s = b.add_u64("thread_count");        if (!s) return s;
            s = b.add_u64("cnode_count");         if (!s) return s;
        }
        s = b.add_bytes("name", 16);  if (!s) return s;
        s = b.add_bytes("uuid", 16);  if (!s) return s;
        if (!is_old) {
            s = b.add_u64("source_version"); if (!s) return s;
        }
        s = b.save("SEPRootserver"); if (!s) return s;
    }

    // --- SEPDynamicObject struct ---
    {
        auto s = save_named_struct("SEPDynamicObject", {
            {0, "handle", u32_type()}, {4, "sep_offset", u32_type()},
            {8, "dart_offset", u32_type()}, {12, "sep_size", u32_type()},
        });
        if (!s) return s;
    }

    // --- Legion64BootArgs struct (covers the entire boot segment header) ---
    {
        StructBuilder b(ida::type::TypeInfo::create_struct());
        std::size_t hdr_rel = hdr_offset - static_cast<std::size_t>(kBootStart);

        // Pre-header fields
        b.seek(0x00); auto s = b.add_u64("uuid_offset");              if (!s) return s;
        b.seek(0x08); s = b.add_bytes("astris_uuid", 16);             if (!s) return s;
        b.seek(0x38); s = b.add_u32("subversion");                    if (!s) return s;
        b.seek(0x3C); s = b.add_bytes("legion_string", 16);           if (!s) return s;
        b.seek(0x4C); s = b.add_u16("sepos_boot_args_offset");        if (!s) return s;
        b.seek(0x4E); s = b.add_bytes("_legion_reserved", 2);         if (!s) return s;

        // Kernel/firmware metadata block
        b.seek(hdr_rel);
        s = b.add_bytes("kern_uuid", 16);                             if (!s) return s;
        s = b.add_u64("kern_heap_size");                               if (!s) return s;
        s = b.add_u64("kern_ro_start");                                if (!s) return s;
        s = b.add_u64("kern_ro_end");                                  if (!s) return s;
        s = b.add_u64("app_ro_start");                                 if (!s) return s;
        s = b.add_u64("app_ro_end");                                   if (!s) return s;
        s = b.add_u64("end_of_payload");                               if (!s) return s;
        s = b.add_u64("required_tz0_size");                            if (!s) return s;
        s = b.add_u64("required_tz1_size");                            if (!s) return s;
        s = b.add_u64("required_ar_plaintext_size");                   if (!s) return s;

        auto ar_min_size = read_u64_le(fw, hdr_offset + 16 + 8 * 8);
        if (ar_min_size != 0 || ver == 4) {
            s = b.add_u64("required_non_ar_plaintext_size");           if (!s) return s;
            s = b.add_u64("shm_base");                                 if (!s) return s;
            s = b.add_u64("shm_size");                                 if (!s) return s;
        }

        // Embedded rootserver info
        auto root_type = ida::type::TypeInfo::by_name("SEPRootserver");
        if (!root_type) return std::unexpected(root_type.error());
        auto root_size = root_type->size();
        if (!root_size) return std::unexpected(root_size.error());
        s = b.add("rootserver_info", *root_type, *root_size);         if (!s) return s;

        s = b.add_u32("sepos_crc32");                                  if (!s) return s;
        s = b.add_u32("kern_no_ar_mem");                               if (!s) return s;

        // Dynamic objects array
        auto dyn = ida::type::TypeInfo::by_name("SEPDynamicObject");
        if (!dyn) return std::unexpected(dyn.error());
        s = b.add("dynamic_objects", ida::type::TypeInfo::array_of(*dyn, 16), 0x100);
        if (!s) return s;

        s = b.add_u32("num_apps");                                     if (!s) return s;
        s = b.add_u32("num_shlibs");                                   if (!s) return s;

        // App list array
        auto sepapp_type = ida::type::TypeInfo::by_name("SEPApp64");
        if (!sepapp_type) return std::unexpected(sepapp_type.error());
        std::size_t total = stride * static_cast<std::size_t>(n_apps + n_shlibs);
        s = b.add("app_list", ida::type::TypeInfo::array_of(*sepapp_type, n_apps + n_shlibs), total);
        if (!s) return s;

        s = b.save("Legion64BootArgs");
        if (!s) return s;
    }

    return apply_named_type_at(kBootStart, "Legion64BootArgs");
}

// ============================================================================
// The SEP firmware loader
// ============================================================================

class SepFirmwareLoader final : public ida::loader::Loader {
public:
    ida::Result<std::optional<ida::loader::AcceptResult>>
    accept(ida::loader::InputFile& file) override {
        auto probe = file.read_bytes_at(0, 0x1200);
        if (!probe) return std::nullopt;
        if (!is_sep_firmware(*probe)) return std::nullopt;

        return ida::loader::AcceptResult{
            .format_name    = "Apple SEP firmware [idax example]",
            .processor_name = "arm",
            .priority       = 100,
        };
    }

    ida::Status load(ida::loader::InputFile& file, std::string_view /*format_name*/) override {
        auto processor = ida::loader::set_processor("arm");
        if (!processor) return processor;

        auto file_size = file.size();
        if (!file_size) return std::unexpected(file_size.error());

        auto firmware = file.read_bytes_at(0, static_cast<std::size_t>(*file_size));
        if (!firmware) return std::unexpected(firmware.error());

        auto modules = extract_all_modules(*firmware);
        if (!modules) return std::unexpected(modules.error());

        ida::loader::create_filename_comment();
        (void)define_macho_header_types();
        ida::ui::message(fmt("[SEP loader] found %zu modules\n", modules->size()));

        auto shlib = resolve_shared_library(*firmware, *modules);

        std::uint64_t ordinal = 0;
        for (const auto& mod : *modules) {
            auto s = load_module(file, *firmware, mod, shlib, ordinal);
            if (!s) return s;
        }

        (void)define_firmware_types(*firmware);
        return ida::ok();
    }

private:
    // ----------------------------------------------------------------
    // Shared library cache resolution
    // ----------------------------------------------------------------

    static SharedLibraryInfo
    resolve_shared_library(std::span<const std::uint8_t> firmware,
                           const std::vector<SepModule>& modules) {
        SharedLibraryInfo info;
        for (const auto& mod : modules) {
            if (!mod.is_shlib || !mod.is_macho || mod.phys_text >= firmware.size())
                continue;

            auto raw = firmware_slice(firmware, mod);
            auto macho = parse_macho(raw);
            if (!macho) continue;

            info.base = sep::kRelocStep * mod.slot;
            if (auto lc_off = find_lc_sep_slide(raw))
                info.slide = compute_shared_cache_slide(*lc_off, mod.virt != 0 ? mod.virt : 0x8000);
            break;
        }
        return info;
    }

    // ----------------------------------------------------------------
    // Per-module loading dispatch
    // ----------------------------------------------------------------

    ida::Status load_module(ida::loader::InputFile& file,
                            std::span<const std::uint8_t> firmware,
                            const SepModule& mod,
                            const SharedLibraryInfo& shlib,
                            std::uint64_t& ordinal) {
        ida::ui::message(fmt("[SEP loader] loading %-6s %s\n", mod.kind.c_str(), mod.name.c_str()));

        if (mod.kind == "boot")
            return map_raw(file, 0, 0, mod.size_text, "SEPBOOT", true, mod, ordinal, firmware.size());

        if (!mod.is_macho)
            return map_raw(file, mod.phys_text, mod.phys_text, mod.size_text,
                           mod.name, true, mod, ordinal, firmware.size());

        if (mod.phys_text >= firmware.size())
            return std::unexpected(ida::Error::validation("SEP module text offset is out of range", mod.name));

        auto raw = firmware_slice(firmware, mod);
        auto macho = parse_macho(raw);
        if (!macho) {
            ida::ui::message(fmt("[SEP loader] Mach-O parse failed for %s, mapping raw\n", mod.name.c_str()));
            return map_raw(file, mod.phys_text, sep::kRelocStep * mod.slot, mod.size_text,
                           mod.name, true, mod, ordinal, firmware.size());
        }

        return load_macho_module(file, firmware, mod, *macho, shlib, ordinal);
    }

    // ----------------------------------------------------------------
    // Mach-O module loading
    // ----------------------------------------------------------------

    ida::Status load_macho_module(ida::loader::InputFile& file,
                                  std::span<const std::uint8_t> firmware,
                                  const SepModule& mod,
                                  const MachOBinary& macho,
                                  const SharedLibraryInfo& shlib,
                                  std::uint64_t& ordinal) {
        const ida::Address module_base = sep::kRelocStep * mod.slot;
        const ida::Address imagebase   = module_base + macho.imagebase;

        // Determine header extent (up to first section data)
        std::uint64_t hdr_size = compute_header_extent(macho, mod.size_text);

        // Find __text section VA range for PAC pointer resolution
        auto [text_start, text_end] = find_text_section_range(macho);

        // Map segments
        for (const auto& seg : macho.segments) {
            auto s = load_segment(file, firmware, mod, seg, module_base, imagebase, shlib,
                                  text_start, text_end);
            if (!s) return s;
        }

        // Annotate Mach-O header
        if (hdr_size != 0) {
            (void)apply_named_type_at(imagebase, "mach_header_64");
            (void)ida::name::force_set(imagebase, safe_symbol_name(mod.name + "_mach_header", "mach_header"));
            (void)annotate_macho_load_commands(
                imagebase,
                std::span<const std::uint8_t>(firmware.data() + static_cast<std::size_t>(mod.phys_text),
                                              static_cast<std::size_t>(hdr_size)));
        }

        // Register entry point
        register_entry_point(macho, module_base, mod.name, ordinal);

        // Import symbols
        for (const auto& [name, value] : macho.symbols) {
            ida::Address ea = module_base + value;
            if (ea == module_base) continue;
            ida::name::force_set(ea, safe_symbol_name(name, mod.name + "_symbol"));
        }

        return ida::ok();
    }

    // ----------------------------------------------------------------
    // Segment loading + section fixups
    // ----------------------------------------------------------------

    ida::Status load_segment(ida::loader::InputFile& file,
                             std::span<const std::uint8_t> firmware,
                             const SepModule& mod,
                             const MachOSegment& seg,
                             ida::Address module_base,
                             ida::Address imagebase,
                             const SharedLibraryInfo& shlib,
                             std::optional<std::uint64_t> text_start,
                             std::optional<std::uint64_t> text_end) {
        if (seg.name == "__PAGEZERO" || seg.name == "__LINKEDIT")
            return ida::ok();

        const ida::Address start = module_base + seg.vmaddr;
        const auto vsize = static_cast<ida::AddressSize>(seg.vmsize != 0 ? seg.vmsize : seg.filesize);
        if (vsize == 0) return ida::ok();

        // Create IDA segment
        auto s = create_or_update_segment(
            start, start + vsize,
            safe_symbol_name(mod.name + "_" + seg.name, "sep_segment"),
            segment_class_for(seg), segment_type_for(seg), permissions_for(seg.initprot));
        if (!s) return s;

        // Load file-backed data
        if (seg.filesize > 0) {
            auto fw_off = fw_offset_for(seg.fileoff, mod);
            auto load_size = static_cast<ida::AddressSize>(std::min<std::uint64_t>(seg.filesize, vsize));
            auto ls = ida::loader::file_to_database(
                file.handle(), static_cast<std::int64_t>(fw_off), start, load_size, true);
            if (!ls) return ls;
        }

        // Zero-fill BSS region
        if (seg.vmsize > seg.filesize) {
            std::vector<std::uint8_t> zeros(static_cast<std::size_t>(seg.vmsize - seg.filesize), 0);
            auto zs = ida::loader::memory_to_database(zeros.data(), start + seg.filesize, zeros.size());
            if (!zs) return zs;
        }

        // Segment comment
        std::string comment = fmt("SEP %s module '%s' (%s)", mod.kind.c_str(), mod.name.c_str(), seg.name.c_str());
        if (!mod.uuid.empty()) comment += fmt(", uuid=%s", mod.uuid.c_str());
        ida::segment::set_comment(start, comment);

        // Per-section annotation and fixups
        for (const auto& section : seg.sections)
            apply_section_fixups(section, mod, module_base, imagebase, shlib, text_start, text_end);

        return ida::ok();
    }

    void apply_section_fixups(const MachOSection& section,
                              const SepModule& mod,
                              ida::Address module_base,
                              ida::Address imagebase,
                              const SharedLibraryInfo& shlib,
                              std::optional<std::uint64_t> text_start,
                              std::optional<std::uint64_t> text_end) {
        if (section.size == 0) return;

        ida::Address section_ea = module_base + section.address;
        std::size_t qword_count = static_cast<std::size_t>(section.size / 8);

        // Name and comment
        (void)ida::name::force_set(
            section_ea,
            safe_symbol_name(mod.name + "_" + section.segment_name + "_" + section.name, "sep_section"));
        ida::comment::add_anterior(
            section_ea,
            fmt("%s:%s:%s", mod.name.c_str(), section.segment_name.c_str(), section.name.c_str()));

        // Initializer / auth pointer fixups
        if (section.name == "__mod_init_func" || section.name == "__init_offsets" || section.name == "__auth_ptr") {
            (void)rewrite_qwords(section_ea, qword_count, rewriters::init_pointer(imagebase), true);
        }

        // GOT resolution via shared library cache
        if ((section.name == "__auth_got" || section.name == "__got") && shlib.base != 0) {
            (void)rewrite_qwords(section_ea, qword_count, rewriters::got_shlib(shlib), true);
        }

        // PAC-tagged constant pointers
        if (section.name == "__const" && text_start && text_end) {
            (void)rewrite_qwords(section_ea, qword_count,
                                 rewriters::pac_const(imagebase, *text_start, *text_end), true);
        }
    }

    // ----------------------------------------------------------------
    // Raw (non-Mach-O) region mapping
    // ----------------------------------------------------------------

    static ida::Status map_raw(ida::loader::InputFile& file,
                               std::uint64_t file_offset, ida::Address start, std::uint64_t size,
                               std::string_view segment_name, bool executable,
                               const SepModule& mod, std::uint64_t& ordinal,
                               std::size_t firmware_size) {
        if (size == 0) return ida::ok();
        if (file_offset >= firmware_size)
            return std::unexpected(ida::Error::validation("SEP raw module offset is out of range", mod.name));

        size = std::min<std::uint64_t>(size, firmware_size - file_offset);

        auto s = create_or_update_segment(
            start, start + size,
            safe_symbol_name(segment_name, "sep_raw"),
            executable ? "CODE" : "DATA",
            executable ? ida::segment::Type::Code : ida::segment::Type::Data,
            {.read = true, .write = !executable, .execute = executable});
        if (!s) return s;

        auto ls = ida::loader::file_to_database(
            file.handle(), static_cast<std::int64_t>(file_offset), start,
            static_cast<ida::AddressSize>(size), true);
        if (!ls) return ls;

        std::string comment = fmt("SEP %s module '%s'", mod.kind.c_str(), mod.name.c_str());
        if (!mod.uuid.empty()) comment += fmt(", uuid=%s", mod.uuid.c_str());
        ida::segment::set_comment(start, comment);

        if (executable) {
            auto entry_name = safe_symbol_name(mod.name + "_start", "sep_entry");
            ida::entry::add(ordinal++, start, entry_name, true);
            ida::name::force_set(start, entry_name);
            ida::analysis::schedule_function(start);
        }
        return ida::ok();
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    /// Slice the firmware buffer to the raw Mach-O region for a module.
    static std::span<const std::uint8_t>
    firmware_slice(std::span<const std::uint8_t> firmware, const SepModule& mod) {
        auto available = firmware.size() - static_cast<std::size_t>(mod.phys_text);
        auto raw_size = static_cast<std::size_t>(std::min<std::uint64_t>(available, mod.size_text));
        return {firmware.data() + static_cast<std::size_t>(mod.phys_text), raw_size};
    }

    /// Compute the Mach-O header extent (bytes before first section data).
    static std::uint64_t compute_header_extent(const MachOBinary& macho, std::uint64_t max_size) {
        std::uint64_t hdr_size = 0x100;
        bool found = false;
        for (const auto& seg : macho.segments)
            for (const auto& sect : seg.sections)
                if (sect.offset > 0 && (!found || sect.offset < hdr_size)) {
                    hdr_size = sect.offset;
                    found = true;
                }
        return std::min(hdr_size, max_size);
    }

    /// Find the VA range of the __text section (for PAC pointer validation).
    static std::pair<std::optional<std::uint64_t>, std::optional<std::uint64_t>>
    find_text_section_range(const MachOBinary& macho) {
        for (const auto& seg : macho.segments)
            for (const auto& sect : seg.sections)
                if (sect.name == "__text")
                    return {sect.address, sect.address + sect.size};
        return {std::nullopt, std::nullopt};
    }

    /// Register the module entry point with IDA.
    static void register_entry_point(const MachOBinary& macho, ida::Address module_base,
                                     const std::string& mod_name, std::uint64_t& ordinal) {
        ida::Address entry = ida::BadAddress;
        if (macho.entry_pc)
            entry = module_base + *macho.entry_pc;
        else if (macho.entry_main)
            entry = module_base + macho.imagebase + *macho.entry_main;

        if (entry == ida::BadAddress) return;

        auto name = safe_symbol_name(mod_name + "_start", "sep_entry");
        ida::entry::add(ordinal++, entry, name, true);
        ida::name::force_set(entry, name);
        ida::analysis::schedule_function(entry);
    }
};

} // namespace

IDAX_LOADER(SepFirmwareLoader)
