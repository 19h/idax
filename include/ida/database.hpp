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

/// MD5 hash of the original input file (hex string).
Result<std::string> input_md5();

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
