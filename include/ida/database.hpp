/// \file database.hpp
/// \brief Database lifecycle and metadata operations.
///
/// Wraps idalib.hpp and ida.hpp infrastructure fields for database
/// open/close/save and metadata queries.

#ifndef IDAX_DATABASE_HPP
#define IDAX_DATABASE_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <string>
#include <string_view>

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

} // namespace ida::database

#endif // IDAX_DATABASE_HPP
