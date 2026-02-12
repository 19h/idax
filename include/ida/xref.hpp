/// \file xref.hpp
/// \brief Cross-reference enumeration and mutation.

#ifndef IDAX_XREF_HPP
#define IDAX_XREF_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <vector>

namespace ida::xref {

// ── Types ───────────────────────────────────────────────────────────────

enum class CodeType {
    CallFar,
    CallNear,
    JumpFar,
    JumpNear,
    Flow,
};

enum class DataType {
    Offset,
    Write,
    Read,
    Text,
    Informational,
};

/// Unified cross-reference descriptor.
struct Reference {
    Address from{};
    Address to{};
    bool    is_code{false};
    int     raw_type{0};    ///< SDK cref_t or dref_t value.
    bool    user_defined{false};
};

// ── Mutation ────────────────────────────────────────────────────────────

Status add_code(Address from, Address to, CodeType type);
Status add_data(Address from, Address to, DataType type);
Status remove_code(Address from, Address to);
Status remove_data(Address from, Address to);

// ── Enumeration ─────────────────────────────────────────────────────────

/// All references originating from \p ea.
Result<std::vector<Reference>> refs_from(Address ea);

/// All references targeting \p ea.
Result<std::vector<Reference>> refs_to(Address ea);

/// Only code references from \p ea.
Result<std::vector<Reference>> code_refs_from(Address ea);

/// Only code references to \p ea.
Result<std::vector<Reference>> code_refs_to(Address ea);

/// Only data references from \p ea.
Result<std::vector<Reference>> data_refs_from(Address ea);

/// Only data references to \p ea.
Result<std::vector<Reference>> data_refs_to(Address ea);

} // namespace ida::xref

#endif // IDAX_XREF_HPP
