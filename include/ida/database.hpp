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

/// Initialise the IDA library (call once, before any other idax call).
/// Wraps init_library().
Status init(int argc = 0, char* argv[] = nullptr);

/// Open (or create) a database for the given input file.
/// If \p auto_analysis is true the auto-analyser runs to completion.
/// Wraps open_database().
Status open(std::string_view path, bool auto_analysis = true);

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
