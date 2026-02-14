/// \file name.hpp
/// \brief Naming, demangling, and name property operations.

#ifndef IDAX_NAME_HPP
#define IDAX_NAME_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace ida::name {

// ── Demangle form ───────────────────────────────────────────────────────

enum class DemangleForm {
    Short,
    Long,
    Full,
};

// ── Core naming ─────────────────────────────────────────────────────────

/// Set or replace the name at \p address.
Status set(Address address, std::string_view name);

/// Force-set a name at \p address, appending a numeric suffix if the name is taken.
Status force_set(Address address, std::string_view name);

/// Remove the name at \p address.
Status remove(Address address);

/// Get the name at \p address.
Result<std::string> get(Address address);

/// Get the demangled name at \p address.
Result<std::string> demangled(Address address, DemangleForm form = DemangleForm::Short);

/// Resolve a name to an address.
Result<Address> resolve(std::string_view name, Address context = BadAddress);

// ── Name inventory ───────────────────────────────────────────────────────

/// Enumerated name entry.
struct Entry {
    Address     address{BadAddress};
    std::string name;
    bool        user_defined{false};
    bool        auto_generated{false};
};

/// Options for name inventory enumeration.
/// If start/end are BadAddress, the full inventory is returned.
/// Address filtering uses a half-open range [start, end).
struct ListOptions {
    Address start{BadAddress};
    Address end{BadAddress};
    bool    include_user_defined{true};
    bool    include_auto_generated{true};
};

/// Enumerate names with typed filtering options.
Result<std::vector<Entry>> all(const ListOptions& options = {});

/// Enumerate only user-defined names, optionally in [start, end).
Result<std::vector<Entry>> all_user_defined(Address start = BadAddress,
                                            Address end = BadAddress);

// ── Name properties ─────────────────────────────────────────────────────

bool is_public(Address address);
bool is_weak(Address address);
bool is_user_defined(Address address);
bool is_auto_generated(Address address);

/// Validate a user-facing identifier according to IDA naming rules.
Result<bool> is_valid_identifier(std::string_view text);

/// Normalize an identifier by replacing invalid characters where possible.
Result<std::string> sanitize_identifier(std::string_view text);

Status set_public(Address address, bool value = true);
Status set_weak(Address address, bool value = true);

} // namespace ida::name

#endif // IDAX_NAME_HPP
