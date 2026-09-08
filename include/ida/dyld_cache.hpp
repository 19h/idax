/// \file dyld_cache.hpp
/// \brief Apple dyld shared-cache image inventory and incremental loading.
#ifndef IDAX_DYLD_CACHE_HPP
#define IDAX_DYLD_CACHE_HPP

#include <ida/address.hpp>
#include <ida/error.hpp>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace ida::dyld_cache {

struct ModuleInfo {
    std::string path;
    Address load_address{BadAddress}; ///< Unslid address offline; database address online.
};

/// Whether the current database provides the public shared-cache service.
/// Requires SDK 9.4 or later and a database opened by the dyld cache loader.
bool is_available();

/// Owned image inventory from the current database's cache service.
Result<std::vector<ModuleInfo>> list_modules();

/// Read an image inventory directly from a toplevel cache file without an IDB.
/// Supports modern, legacy, and image-text tables. Malformed input fails as a
/// whole; paths must be absolute, NUL-terminated, and at most 65536 bytes.
Result<std::vector<ModuleInfo>> list_modules(std::string_view cache_path);

Status load_module(std::string_view module_path, bool wait_for_analysis = false);

/// Load the region containing address. Image sections load the entire image,
/// as required by the shared-cache service's atomic image-loading contract.
Status load_section(Address address, bool wait_for_analysis = false);

/// Verify the header loaded by the cache loader is mapped in the database.
/// The SDK does not provide a separate header-loading operation.
Status load_dyld_header(bool wait_for_analysis = false);

/// Load matching regions in one atomic SDK request. Return the number of
/// unique previously unloaded entities loaded; an empty request returns zero.
/// If waiting is requested, analysis cancellation is reported as an error.
Result<std::size_t> load_branch_islands(bool wait_for_analysis = false);
Result<std::size_t> load_branch_mappings(bool wait_for_analysis = false);
Result<std::size_t> load_global_offset_tables(bool wait_for_analysis = false);
Result<std::size_t> load_gaps(bool wait_for_analysis = false);
Result<std::size_t> load_cache_data(bool wait_for_analysis = false);

} // namespace ida::dyld_cache
#endif
