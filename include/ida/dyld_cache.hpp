/// \file dyld_cache.hpp
/// \brief dyld shared cache utilities — programmatic access to the bundled
///        IDA "dscu" plugin.
///
/// IDA ships a "dscu" (dyld shared cache utils) plugin that becomes available
/// when a database is opened from a dyld shared cache using the "single
/// module" option. This namespace exposes that plugin's functionality as a
/// typed, programmatic API: enumerate the cache's modules and load modules,
/// regions, branch islands, branch mappings, global offset tables, unknown
/// regions, cache-wide data, and the cache header into the database.
///
/// All operations are deterministic and require no GUI interaction — the
/// "load all" operations bypass IDA's interactive chooser dialogs, so they
/// behave identically in GUI plugins and in headless (idalib) tools.
///
/// Every function fails with an Unsupported error when the current database
/// was not opened from a dyld shared cache. Check is_available() first.
///
/// Example:
/// ```cpp
/// #include <ida/dyld_cache.hpp>
///
/// if (ida::dyld_cache::is_available()) {
///     ida::dyld_cache::load_module("/usr/lib/libobjc.A.dylib");
///     ida::dyld_cache::load_branch_islands();
/// }
/// ```

#ifndef IDAX_DYLD_CACHE_HPP
#define IDAX_DYLD_CACHE_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace ida::dyld_cache {

// ── Module enumeration ──────────────────────────────────────────────────

/// A single image (module) contained in a dyld shared cache.
struct ModuleInfo {
    std::string path;  ///< Full path inside the cache (e.g. "/usr/lib/libobjc.A.dylib").
    Address     load_address{BadAddress};  ///< Mach-O header address within the cache.
};

// ── Availability ────────────────────────────────────────────────────────

/// Whether dyld shared cache utilities are available for the current database.
///
/// Returns true only when the database was opened from a dyld shared cache
/// with the "single module" option (which loads the bundled "dscu" plugin).
/// When this returns false, every other function here fails with an
/// Unsupported error.
bool is_available();

// ── Queries ─────────────────────────────────────────────────────────────

/// Enumerate every module (image) contained in the dyld shared cache.
///
/// Parses the cache header of the input file directly, so it works before
/// any module has been loaded. Use the returned paths with load_module().
Result<std::vector<ModuleInfo>> list_modules();

/// Enumerate every module in a dyld shared cache file without an open database.
///
/// @param cache_path  File-system path to the dyld shared cache.
/// @return Every image path and load address recorded by the cache header.
Result<std::vector<ModuleInfo>> list_modules(std::string_view cache_path);

// ── Loading ─────────────────────────────────────────────────────────────
//
// Every load_* operation accepts `wait_for_analysis` (default: false).
// dscu maps regions and creates segments synchronously, then queues
// auto-analysis for the new code. Setting `wait_for_analysis = true`
// drains that queue before returning, ensuring the database is in a
// quiescent, fully-analysed state. The default is false because draining
// the queue on a multi-gigabyte macOS shared cache can take tens of
// minutes (CPU-bound, looks like a hang). Callers that need analysis
// completed can either pass `true` or invoke ida::analysis::wait()
// explicitly when they are done batching loads.

/// Load one module (image) from the shared cache by its full path.
///
/// The path is validated against the cache's image directory; an unknown
/// path returns a NotFound error without touching the database. Success is
/// verified by checking that a segment exists at the module's load address,
/// so paths that live only in the new-format `dyld_cache_image_text_info`
/// table (where dscu's mode-1 chooser cannot find them) are still loaded
/// correctly on modern macOS caches.
///
/// @param module_path        Full path inside the cache, e.g.
///                            "/usr/lib/libobjc.A.dylib" (see list_modules()).
/// @param wait_for_analysis  Drain the auto-analysis queue before returning.
Status load_module(std::string_view module_path,
                   bool wait_for_analysis = false);

/// Load the shared-cache region that contains \p address.
///
/// The region kind — a module section, branch island, branch mapping,
/// global offset table, unknown region, or cache-wide data region — is
/// detected automatically from the
/// address. This is the quickest way to resolve a single reference that
/// shows up as `MEMORY[0x...]` in the disassembly.
///
/// @param address            Any address that falls inside the desired region.
/// @param wait_for_analysis  Drain the auto-analysis queue before returning.
Status load_section(Address address, bool wait_for_analysis = false);

/// Load the formatted `dyld_cache_header` structure into the database.
///
/// Requires the initial auto-analysis to have completed.
///
/// @param wait_for_analysis  Drain the auto-analysis queue before returning.
Status load_dyld_header(bool wait_for_analysis = false);

/// Load every branch-island region from the shared cache.
///
/// Branch islands are intermediate stub sequences that bridge calls between
/// distant modules; loading them resolves indirect branches.
///
/// @param wait_for_analysis  Drain the auto-analysis queue before returning.
/// @return The number of branch-island regions loaded.
Result<std::size_t> load_branch_islands(bool wait_for_analysis = false);

/// Load every branch-mapping region from the shared cache (iOS 16+).
///
/// Branch mappings carry stub code that routes calls between cache modules.
///
/// @param wait_for_analysis  Drain the auto-analysis queue before returning.
/// @return The number of branch-mapping regions loaded.
Result<std::size_t> load_branch_mappings(bool wait_for_analysis = false);

/// Load every global-offset-table region from the shared cache (iOS 16+).
///
/// @param wait_for_analysis  Drain the auto-analysis queue before returning.
/// @return The number of global-offset-table regions loaded.
Result<std::size_t> load_global_offset_tables(bool wait_for_analysis = false);

/// Load every unknown region from the shared cache.
///
/// IDA 9.4 calls these unknown regions: their address ranges are covered by
/// cache mappings, but their contents are not associated with a known image
/// or auxiliary region type. The historical `load_gaps` name is preserved for
/// source compatibility with IDA 9.3.
///
/// @param wait_for_analysis  Drain the auto-analysis queue before returning.
/// @return The number of gap regions loaded.
Result<std::size_t> load_gaps(bool wait_for_analysis = false);

/// Load every cache-wide data region from the shared cache.
///
/// Cache-wide data regions include named data shared by the cache as a whole,
/// such as linkedit subcache mappings. This region type was introduced by the
/// public IDA 9.4 DSC service. Builds made with an older IDA SDK return an
/// Unsupported error.
///
/// @param wait_for_analysis  Drain the auto-analysis queue before returning.
/// @return The number of cache-wide data regions loaded.
Result<std::size_t> load_cache_data(bool wait_for_analysis = false);

} // namespace ida::dyld_cache

#endif // IDAX_DYLD_CACHE_HPP
