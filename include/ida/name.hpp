/// \file name.hpp
/// \brief Naming, demangling, and name property operations.

#ifndef IDAX_NAME_HPP
#define IDAX_NAME_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <string>
#include <string_view>

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
