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

/// Set or replace the name at \p ea.
Status set(Address ea, std::string_view name);

/// Force-set a name at \p ea, appending a numeric suffix if the name is taken.
Status force_set(Address ea, std::string_view name);

/// Remove the name at \p ea.
Status remove(Address ea);

/// Get the name at \p ea.
Result<std::string> get(Address ea);

/// Get the demangled name at \p ea.
Result<std::string> demangled(Address ea, DemangleForm form = DemangleForm::Short);

/// Resolve a name to an address.
Result<Address> resolve(std::string_view name, Address context = BadAddress);

// ── Name properties ─────────────────────────────────────────────────────

bool is_public(Address ea);
bool is_weak(Address ea);
bool is_auto_generated(Address ea);

Status set_public(Address ea, bool value = true);
Status set_weak(Address ea, bool value = true);

} // namespace ida::name

#endif // IDAX_NAME_HPP
