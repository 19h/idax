/// \file loader.hpp
/// \brief Loader module development helpers.
///
/// Provides the Loader base class for custom file format loaders and
/// InputFile abstraction for reading input files.
///
/// To create a custom loader:
/// 1. Subclass ida::loader::Loader
/// 2. Override accept() and load() (optionally save() and move_segment())
/// 3. Use IDAX_LOADER(YourLoader) macro at file scope to export the loader

#ifndef IDAX_LOADER_HPP
#define IDAX_LOADER_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida::loader {

// ── Input file abstraction ──────────────────────────────────────────────

/// Opaque wrapper around the SDK input handle for reading input files.
///
/// Instances are provided to Loader callbacks — users do not create them.
class InputFile {
public:
    /// Total size of the input file in bytes.
    [[nodiscard]] Result<std::int64_t> size() const;

    /// Current read position in the file.
    [[nodiscard]] Result<std::int64_t> tell() const;

    /// Seek to an absolute position. Returns the new position.
    Result<std::int64_t> seek(std::int64_t offset);

    /// Read up to \p count bytes into a vector starting at current position.
    Result<std::vector<std::uint8_t>> read_bytes(std::size_t count);

    /// Read up to \p count bytes from a given offset (seeks first).
    Result<std::vector<std::uint8_t>> read_bytes_at(std::int64_t offset,
                                                     std::size_t count);

    /// Read a null-terminated string starting at \p offset, up to \p max_len.
    Result<std::string> read_string(std::int64_t offset,
                                    std::size_t max_len = 1024) const;

    /// The file name (may be a temporary file for archive members).
    [[nodiscard]] Result<std::string> filename() const;

    /// Get the opaque handle for use with file_to_database().
    [[nodiscard]] void* handle() const noexcept { return handle_; }

private:
    friend struct InputFileAccess;
    void* handle_{nullptr};  ///< Opaque SDK input handle.
};

// ── Loader accept result ────────────────────────────────────────────────

/// Result returned by Loader::accept() when the loader recognises the file.
struct AcceptResult {
    std::string format_name;     ///< Name shown in the "load file" dialog.
    std::string processor_name;  ///< Desired processor (optional, empty = any).
    int         priority{0};     ///< Higher = preferred.
    bool        archive_loader{false};   ///< Corresponds to SDK ACCEPT_ARCHIVE.
    bool        continue_probe{false};   ///< Corresponds to SDK ACCEPT_CONTINUE.
    bool        prefer_first{false};     ///< Corresponds to SDK ACCEPT_FIRST.
};

// ── Loader flags ────────────────────────────────────────────────────────

/// Options for the Loader base class.
struct LoaderOptions {
    bool supports_reload{false};    ///< Loader recognizes reload requests.
    bool requires_processor{false}; ///< Loader requires a processor to be set beforehand.
};

/// Decoded load-file flags (SDK `NEF_*`) exposed as typed booleans.
struct LoadFlags {
    bool create_segments{false};
    bool load_resources{false};
    bool rename_entries{false};
    bool manual_load{false};
    bool fill_gaps{false};
    bool create_import_segment{false};
    bool first_file{false};
    bool binary_code_segment{false};
    bool reload{false};
    bool auto_flat_group{false};
    bool mini_database{false};
    bool loader_options_dialog{false};
    bool load_all_segments{false};
};

/// Rich load request that models normal, reload, and archive-member flows.
struct LoadRequest {
    std::string format_name;
    std::string input_name;
    std::string archive_name;
    std::string archive_member_name;
    LoadFlags flags{};
    bool is_remote{false};
};

/// Save request metadata.
struct SaveRequest {
    std::string format_name;
    bool capability_query{false};
    bool is_remote{false};
};

/// Segment move/rebase request metadata.
struct MoveSegmentRequest {
    std::string format_name;
    bool whole_program_rebase{false};
    bool reload{false};
};

/// Archive extraction request metadata.
struct ArchiveMemberRequest {
    std::string archive_name;
    std::string default_member;
    LoadFlags flags{};
};

/// Archive extraction result metadata.
struct ArchiveMemberResult {
    std::string extracted_file;
    std::string member_name;
    LoadFlags flags{};
};

/// Decode raw SDK `NEF_*` bits into typed `LoadFlags`.
LoadFlags decode_load_flags(std::uint16_t raw_flags);

/// Encode typed `LoadFlags` into raw SDK `NEF_*` bits.
std::uint16_t encode_load_flags(const LoadFlags& flags);

// ── Loader base class ───────────────────────────────────────────────────

/// Base class for custom file format loaders.
///
/// Subclass this and override accept() and load(). Optionally override
/// save() and move_segment(). Use the IDAX_LOADER() macro to export.
///
/// Example:
/// \code
/// class MyLoader : public ida::loader::Loader {
/// public:
///     LoaderOptions options() const override { return {}; }
///
///     Result<std::optional<AcceptResult>> accept(InputFile& file) override {
///         auto magic = file.read_bytes_at(0, 4);
///         if (!magic || magic->size() < 4) return std::nullopt;
///         if ((*magic)[0] != 'M') return std::nullopt;
///         return AcceptResult{"My Format", "metapc"};
///     }
///
///     Status load(InputFile& file, std::string_view format_name) override {
///         set_processor("metapc");
///         // Create segments, load bytes, etc.
///         return ida::ok();
///     }
/// };
/// IDAX_LOADER(MyLoader)
/// \endcode
class Loader {
public:
    virtual ~Loader() = default;

    /// Return loader options/flags.
    virtual LoaderOptions options() const { return {}; }

    /// Check if the input file is recognised by this loader.
    /// Return std::nullopt if not recognised, or an AcceptResult describing
    /// the format and desired processor.
    virtual Result<std::optional<AcceptResult>> accept(InputFile& file) = 0;

    /// Load the file into the database.
    /// Called after accept() succeeds and the user selects this format.
    /// @param file  The input file.
    /// @param format_name  The format name from accept().
    virtual Status load(InputFile& file, std::string_view format_name) = 0;

    /// Context-rich load callback for reload/archive/member scenarios.
    ///
    /// Default behavior delegates to `load(file, request.format_name)`.
    virtual Status load_with_request(InputFile& file,
                                     const LoadRequest& request) {
        return load(file, request.format_name);
    }

    /// Optional archive-member extraction callback.
    ///
    /// Default behavior indicates no archive processing support.
    virtual Result<std::optional<ArchiveMemberResult>>
    process_archive(InputFile& file, const ArchiveMemberRequest& request) {
        (void)file;
        (void)request;
        return std::nullopt;
    }

    /// Save the database back to a file (optional).
    /// @param fp  File pointer to write to, or nullptr to query capability.
    /// @param format_name  The format name.
    /// @return When fp is nullptr, returns true if saving is supported.
    virtual Result<bool> save(void* fp, std::string_view format_name) {
        (void)fp; (void)format_name;
        return false;
    }

    /// Context-rich save callback.
    ///
    /// Default behavior delegates to `save(fp, request.format_name)`.
    virtual Result<bool> save_with_request(void* fp,
                                           const SaveRequest& request) {
        return save(fp, request.format_name);
    }

    /// Handle a segment being moved/rebased (optional).
    /// @param from  Original segment start. BadAddress means the entire
    ///              program was rebased (delta is in \p to).
    /// @param to    New segment start (or delta if from == BadAddress).
    /// @param size  Segment size (0 if entire program rebase).
    /// @param format_name  The format name.
    virtual Status move_segment(Address from, Address to, AddressSize size,
                                std::string_view format_name) {
        (void)from; (void)to; (void)size; (void)format_name;
        return std::unexpected(Error::unsupported("move_segment not implemented"));
    }

    /// Context-rich segment move callback.
    ///
    /// Default behavior delegates to `move_segment(..., request.format_name)`.
    virtual Status move_segment_with_request(Address from,
                                             Address to,
                                             AddressSize size,
                                             const MoveSegmentRequest& request) {
        return move_segment(from, to, size, request.format_name);
    }
};

// ── Loader helper functions ─────────────────────────────────────────────

/// Copy bytes from input file to the database at [ea, ea+size).
/// @param li_handle  Opaque SDK input handle (from InputFile::handle()).
/// @param file_offset  Position in the input file.
/// @param ea  Destination address in the database.
/// @param size  Number of bytes to copy.
/// @param patchable  If true, bytes can be patched later.
Status file_to_database(void* li_handle, std::int64_t file_offset,
                        Address ea, AddressSize size, bool patchable = true);

/// Copy memory buffer to the database at [ea, ea+size).
Status memory_to_database(const void* data, Address ea, AddressSize size);

/// Set the processor type for the new database (called from load_file).
Status set_processor(std::string_view processor_name);

/// Add a standard "Input file: ..." comment at the beginning of the database.
Status create_filename_comment();

/// Abort loading with an error message. This function does not return.
[[noreturn]] void abort_load(std::string_view message);

} // namespace ida::loader

/// Registration macro for idax loaders.
/// Place at file scope in your loader source file.
/// The macro creates the loader_t LDSC export symbol that IDA expects.
#define IDAX_LOADER(LoaderClass)                                             \
    namespace {                                                              \
    static LoaderClass g_idax_loader_instance;                               \
    }                                                                        \
    extern "C" {                                                             \
    void idax_loader_bridge_init(void** out_loader, void** out_input);       \
    }                                                                        \
    void idax_loader_bridge_init(void** out_loader, void** out_input) {      \
        *out_loader = &g_idax_loader_instance;                               \
        (void)out_input;                                                     \
    }

#endif // IDAX_LOADER_HPP
