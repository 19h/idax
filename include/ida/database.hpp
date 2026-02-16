/// \file database.hpp
/// \brief Database lifecycle and metadata operations.
///
/// Wraps idalib.hpp and ida.hpp infrastructure fields for database
/// open/close/save and metadata queries.

#ifndef IDAX_DATABASE_HPP
#define IDAX_DATABASE_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ida::database {

// ── Lifecycle ───────────────────────────────────────────────────────────

enum class OpenMode {
    Analyze,
    SkipAnalysis,
};

enum class LoadIntent {
    AutoDetect,
    Binary,
    NonBinary,
};

/// Processor module identifiers (SDK `PLFM_*` values).
///
/// Values match the SDK constants exactly and track the current public set
/// through `PLFM_MCORE`.
enum class ProcessorId : std::int32_t {
    IntelX86            = 0,  ///< `PLFM_386`
    Z80                 = 1,  ///< `PLFM_Z80`
    IntelI860           = 2,  ///< `PLFM_I860`
    Intel8051           = 3,  ///< `PLFM_8051`
    Tms320C5x           = 4,  ///< `PLFM_TMS`
    Mos6502             = 5,  ///< `PLFM_6502`
    Pdp11               = 6,  ///< `PLFM_PDP`
    Motorola68k         = 7,  ///< `PLFM_68K`
    JavaVm              = 8,  ///< `PLFM_JAVA`
    Motorola6800        = 9,  ///< `PLFM_6800`
    St7                 = 10, ///< `PLFM_ST7`
    Motorola68hc12      = 11, ///< `PLFM_MC6812`
    Mips                = 12, ///< `PLFM_MIPS`
    Arm                 = 13, ///< `PLFM_ARM`
    Tms320C6x           = 14, ///< `PLFM_TMSC6`
    PowerPc             = 15, ///< `PLFM_PPC`
    Intel80196          = 16, ///< `PLFM_80196`
    Z8                  = 17, ///< `PLFM_Z8`
    SuperH              = 18, ///< `PLFM_SH`
    DotNet              = 19, ///< `PLFM_NET`
    Avr                 = 20, ///< `PLFM_AVR`
    H8                  = 21, ///< `PLFM_H8`
    Pic                 = 22, ///< `PLFM_PIC`
    Sparc               = 23, ///< `PLFM_SPARC`
    Alpha               = 24, ///< `PLFM_ALPHA`
    Hppa                = 25, ///< `PLFM_HPPA`
    H8500               = 26, ///< `PLFM_H8500`
    TriCore             = 27, ///< `PLFM_TRICORE`
    Dsp56k              = 28, ///< `PLFM_DSP56K`
    C166                = 29, ///< `PLFM_C166`
    St20                = 30, ///< `PLFM_ST20`
    Ia64                = 31, ///< `PLFM_IA64`
    IntelI960           = 32, ///< `PLFM_I960`
    F2mc16              = 33, ///< `PLFM_F2MC`
    Tms320C54x          = 34, ///< `PLFM_TMS320C54`
    Tms320C55x          = 35, ///< `PLFM_TMS320C55`
    Trimedia            = 36, ///< `PLFM_TRIMEDIA`
    M32r                = 37, ///< `PLFM_M32R`
    Nec78k0             = 38, ///< `PLFM_NEC_78K0`
    Nec78k0s            = 39, ///< `PLFM_NEC_78K0S`
    MitsubishiM740      = 40, ///< `PLFM_M740`
    MitsubishiM7700     = 41, ///< `PLFM_M7700`
    St9                 = 42, ///< `PLFM_ST9`
    FujitsuFr           = 43, ///< `PLFM_FR`
    Motorola68hc16      = 44, ///< `PLFM_MC6816`
    MitsubishiM7900     = 45, ///< `PLFM_M7900`
    Tms320C3            = 46, ///< `PLFM_TMS320C3`
    Kr1878              = 47, ///< `PLFM_KR1878`
    Adsp218x            = 48, ///< `PLFM_AD218X`
    OakDsp              = 49, ///< `PLFM_OAKDSP`
    Tlcs900             = 50, ///< `PLFM_TLCS900`
    RockwellC39         = 51, ///< `PLFM_C39`
    Cr16                = 52, ///< `PLFM_CR16`
    Mn10200             = 53, ///< `PLFM_MN102L00`
    Tms320C1x           = 54, ///< `PLFM_TMS320C1X`
    NecV850x            = 55, ///< `PLFM_NEC_V850X`
    ScriptAdapter       = 56, ///< `PLFM_SCR_ADPT`
    EfiBytecode         = 57, ///< `PLFM_EBC`
    Msp430              = 58, ///< `PLFM_MSP430`
    Spu                 = 59, ///< `PLFM_SPU`
    Dalvik              = 60, ///< `PLFM_DALVIK`
    Wdc65c816           = 61, ///< `PLFM_65C816`
    M16c                = 62, ///< `PLFM_M16C`
    Arc                 = 63, ///< `PLFM_ARC`
    Unsp                = 64, ///< `PLFM_UNSP`
    Tms320C28x          = 65, ///< `PLFM_TMS320C28`
    Dsp96000            = 66, ///< `PLFM_DSP96K`
    Spc700              = 67, ///< `PLFM_SPC700`
    Adsp2106x           = 68, ///< `PLFM_AD2106X`
    Pic16               = 69, ///< `PLFM_PIC16`
    S390                = 70, ///< `PLFM_S390`
    Xtensa              = 71, ///< `PLFM_XTENSA`
    RiscV               = 72, ///< `PLFM_RISCV`
    Rl78                = 73, ///< `PLFM_RL78`
    Rx                  = 74, ///< `PLFM_RX`
    Wasm                = 75, ///< `PLFM_WASM`
    Nds32               = 76, ///< `PLFM_NDS32`
    Mcore               = 77, ///< `PLFM_MCORE`
};

/// Headless user-plugin loading policy applied at init time.
///
/// Built-in IDA plugins from IDADIR remain available. This policy only affects
/// discovery of user plugins from IDAUSR. `allowlist_patterns` uses simple
/// wildcard matching (`*` and `?`) against plugin file names.
///
/// Semantics:
/// - `disable_user_plugins=false`, empty allowlist: load all user plugins.
/// - `disable_user_plugins=true`,  empty allowlist: load no user plugins.
/// - non-empty allowlist: load only matching user plugins.
struct PluginLoadPolicy {
    bool disable_user_plugins{false};
    std::vector<std::string> allowlist_patterns;
};

/// Runtime/session options for idalib initialization.
struct RuntimeOptions {
    bool quiet{false};
    PluginLoadPolicy plugin_policy{};
};

/// Normalized target-compiler metadata for the current database.
struct CompilerInfo {
    std::uint32_t id{0};
    bool uncertain{false};
    std::string name;
    std::string abbreviation;
};

/// Imported symbol metadata inside an import module.
struct ImportSymbol {
    Address address{BadAddress};
    std::string name;
    std::uint64_t ordinal{0};
};

/// Imported module metadata.
struct ImportModule {
    std::size_t index{0};
    std::string name;
    std::vector<ImportSymbol> symbols;
};

/// Initialise the IDA library (call once, before any other idax call).
/// Wraps init_library().
Status init(int argc = 0, char* argv[] = nullptr);

/// Initialise the IDA library with explicit runtime options.
Status init(int argc, char* argv[], const RuntimeOptions& options);

/// Initialise the IDA library with runtime options and no argv forwarding.
Status init(const RuntimeOptions& options);

/// Open (or create) a database for the given input file.
/// If \p auto_analysis is true the auto-analyser runs to completion.
/// Wraps open_database().
Status open(std::string_view path, bool auto_analysis = true);

/// Open a database with explicit analysis mode.
Status open(std::string_view path, OpenMode mode);

/// Open a database with explicit load intent and analysis mode.
Status open(std::string_view path,
            LoadIntent intent,
            OpenMode mode = OpenMode::Analyze);

/// Open with explicit binary-input intent.
Status open_binary(std::string_view path, OpenMode mode = OpenMode::Analyze);

/// Open with explicit non-binary-input intent.
Status open_non_binary(std::string_view path, OpenMode mode = OpenMode::Analyze);

/// Save the current database.
/// Wraps save_database().
Status save();

/// Close the current database.
/// \param save  if true the database is saved first.
/// Wraps close_database().
Status close(bool save = false);

/// Load a file range into the database at [ea, ea+size).
Status file_to_database(std::string_view file_path,
                        std::int64_t file_offset,
                        Address ea,
                        AddressSize size,
                        bool patchable = true,
                        bool remote = false);

/// Load bytes from memory into the database at [ea, ea+bytes.size()).
Status memory_to_database(std::span<const std::uint8_t> bytes,
                          Address ea,
                          std::int64_t file_offset = -1);

// ── Metadata ────────────────────────────────────────────────────────────

/// Path of the original input file.
Result<std::string> input_file_path();

/// Human-readable input file type name (for example: "Portable executable").
Result<std::string> file_type_name();

/// Loader-reported format name when provided by the active loader.
Result<std::string> loader_format_name();

/// MD5 hash of the original input file (hex string).
Result<std::string> input_md5();

/// Target compiler metadata inferred/configured for this database.
Result<CompilerInfo> compiler_info();

/// Import-module inventory with per-symbol names/ordinals/addresses.
Result<std::vector<ImportModule>> import_modules();

/// Image base address of the loaded binary.
Result<Address> image_base();

/// Lowest mapped address in the database.
Result<Address> min_address();

/// Highest mapped address in the database.
Result<Address> max_address();

/// Address bounds as a half-open range [min_address, max_address).
Result<ida::address::Range> address_bounds();

/// Span of mapped address space (max_address - min_address).
Result<AddressSize> address_span();

/// Active processor module ID (PLFM_* constant from the SDK).
///
/// Returns the processor ID of the currently loaded processor module.
/// Common IDs: 0 = x86/x64 (Intel), 12 = MIPS, 13 = ARM, 15 = PowerPC.
Result<std::int32_t> processor_id();

/// Active processor module ID as a typed enum.
Result<ProcessorId> processor();

/// Active processor module short name (e.g. "metapc", "ARM", "mips").
Result<std::string> processor_name();

/// Program address bitness for the current database (16/32/64).
Result<int> address_bitness();

/// Endianness of the current database.
Result<bool> is_big_endian();

/// Active ABI name when available (for example: "sysv", "n32", "xbox").
Result<std::string> abi_name();

// ── Snapshot wrappers ────────────────────────────────────────────────────

/// Snapshot metadata and hierarchy node.
struct Snapshot {
    std::int64_t id{0};
    std::uint16_t flags{0};
    std::string description;
    std::string filename;
    std::vector<Snapshot> children;
};

/// Build and return the database snapshot tree.
/// The returned vector contains root-level snapshots.
Result<std::vector<Snapshot>> snapshots();

/// Update the current database snapshot description.
Status set_snapshot_description(std::string_view description);

/// Whether the current database is marked as a snapshot.
Result<bool> is_snapshot_database();

} // namespace ida::database

#endif // IDAX_DATABASE_HPP
